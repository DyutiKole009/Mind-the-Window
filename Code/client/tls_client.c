#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

// =====================================================
// Macros
// =====================================================
#define HTTP_REQUEST "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

// =====================================================
// Structures
// =====================================================
typedef struct {
    char *host;
    int port;
    char *group;
    char *provider_path;
} Args;

typedef struct {
    double tcp_time_ms;
    double tls_time_ms;
    double total_time_ms;
    double rtt_ms;
    int success;
    char error_stage[64];
    char error_msg[256];
} Measurements;

typedef struct {
    int sockfd;
    SSL_CTX *ctx;
    SSL *ssl;
    OSSL_PROVIDER *default_provider;
    OSSL_PROVIDER *oqs_provider;
} Resources;

// =====================================================
// Utility Functions
// =====================================================
double time_diff_ms(struct timespec *start, struct timespec *end) {
    return ((end->tv_sec - start->tv_sec) * 1000.0) +
           ((end->tv_nsec - start->tv_nsec) / 1000000.0);
}

void get_openssl_error(char *buffer, size_t size) {
    unsigned long err = ERR_get_error();
    if (err != 0) {
        ERR_error_string_n(err, buffer, size);
    } else {
        snprintf(buffer, size, "Unknown OpenSSL error");
    }
}

void print_success_json(Measurements *m, const char *cipher, const char *group) {
    printf("{\n");
    printf("    \"success\": true,\n");
    printf("    \"tcp_time_ms\": %.3f,\n", m->tcp_time_ms);
    printf("    \"tls_time_ms\": %.3f,\n", m->tls_time_ms);
    printf("    \"total_time_ms\": %.3f,\n", m->total_time_ms);
    printf("    \"rtt_ms\": %.3f,\n", m->rtt_ms);
    printf("    \"cipher\": \"%s\",\n", cipher);
    printf("    \"group\": \"%s\",\n", group);
    printf("    \"openssl\": \"%s\"\n", OPENSSL_VERSION_TEXT);
    printf("}\n");
}

void print_error_json(Measurements *m) {
    printf("{\n");
    printf("    \"success\": false,\n");
    printf("    \"stage\": \"%s\",\n", m->error_stage);
    printf("    \"error\": \"%s\"\n", m->error_msg);
    printf("}\n");
}

// =====================================================
// CLI Parser
// =====================================================
int parse_arguments(int argc, char **argv, Args *args) {
    memset(args, 0, sizeof(Args));
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) args->host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) args->port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--group") == 0 && i + 1 < argc) args->group = argv[++i];
        else if (strcmp(argv[i], "--provider-path") == 0 && i + 1 < argc) args->provider_path = argv[++i];
    }
    return (args->host && args->port && args->group && args->provider_path);
}

// =====================================================
// Main Execution
// =====================================================
int main(int argc, char **argv) {
    Args args;
    Measurements meas;
    Resources res;
    
    struct timespec t0, t1, t2;
    struct tcp_info tcp_info;
    socklen_t tcp_info_len = sizeof(tcp_info);
    const char *negotiated_cipher = "Unknown";
    
    memset(&meas, 0, sizeof(Measurements));
    memset(&res, 0, sizeof(Resources));
    res.sockfd = -1;

    if (!parse_arguments(argc, argv, &args)) {
        snprintf(meas.error_stage, sizeof(meas.error_stage), "cli_parse");
        snprintf(meas.error_msg, sizeof(meas.error_msg), "Invalid arguments");
        goto cleanup;
    }

    // 1. Load Providers
    OSSL_PROVIDER_set_default_search_path(NULL, args.provider_path);
    res.default_provider = OSSL_PROVIDER_load(NULL, "default");
    res.oqs_provider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    
    if (!res.default_provider || !res.oqs_provider) {
        snprintf(meas.error_stage, sizeof(meas.error_stage), "provider_load");
        get_openssl_error(meas.error_msg, sizeof(meas.error_msg));
        goto cleanup;
    }

    // 2. TCP Connect
    res.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (res.sockfd < 0) {
        snprintf(meas.error_stage, sizeof(meas.error_stage), "socket");
        snprintf(meas.error_msg, sizeof(meas.error_msg), "%s", strerror(errno));
        goto cleanup;
    }

    int flag = 1;
    setsockopt(res.sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args.port);
    inet_pton(AF_INET, args.host, &server_addr.sin_addr);

    clock_gettime(CLOCK_MONOTONIC_RAW, &t0);

    if (connect(res.sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        snprintf(meas.error_stage, sizeof(meas.error_stage), "tcp_connect");
        snprintf(meas.error_msg, sizeof(meas.error_msg), "%s", strerror(errno));
        goto cleanup;
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
    
    if (getsockopt(res.sockfd, IPPROTO_TCP, TCP_INFO, &tcp_info, &tcp_info_len) == 0) {
        meas.rtt_ms = tcp_info.tcpi_rtt / 1000.0;
    }

    // 3. TLS Connect
    res.ctx = SSL_CTX_new(TLS_client_method());
    if (!res.ctx) goto tls_err;

    SSL_CTX_set_verify(res.ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(res.ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(res.ctx, SSL_SESS_CACHE_OFF);

    res.ssl = SSL_new(res.ctx);
    if (!res.ssl) goto tls_err;

    SSL_set_fd(res.ssl, res.sockfd);
    SSL_set1_groups_list(res.ssl, args.group);

    if (SSL_connect(res.ssl) <= 0) goto tls_err;

    clock_gettime(CLOCK_MONOTONIC_RAW, &t2);
    
    negotiated_cipher = SSL_CIPHER_get_name(SSL_get_current_cipher(res.ssl));

    // 4. HTTP Request (Dummy to complete exchange)
    SSL_write(res.ssl, HTTP_REQUEST, strlen(HTTP_REQUEST));
    char buf[256];
    SSL_read(res.ssl, buf, sizeof(buf) - 1);

    // Final Measurements
    meas.tcp_time_ms = time_diff_ms(&t0, &t1);
    meas.tls_time_ms = time_diff_ms(&t1, &t2);
    meas.total_time_ms = time_diff_ms(&t0, &t2);
    meas.success = 1;
    
    goto cleanup;

tls_err:
    snprintf(meas.error_stage, sizeof(meas.error_stage), "tls_connect");
    get_openssl_error(meas.error_msg, sizeof(meas.error_msg));

cleanup:
    if (res.ssl) {
        SSL_shutdown(res.ssl);
        SSL_free(res.ssl);
    }
    if (res.ctx) SSL_CTX_free(res.ctx);
    if (res.sockfd >= 0) close(res.sockfd);
    if (res.oqs_provider) OSSL_PROVIDER_unload(res.oqs_provider);
    if (res.default_provider) OSSL_PROVIDER_unload(res.default_provider);

    if (meas.success) {
        print_success_json(&meas, negotiated_cipher, args.group);
    } else {
        print_error_json(&meas);
    }

    return meas.success ? 0 : 1;
}