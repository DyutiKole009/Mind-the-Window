CC = gcc

CFLAGS = \
    -Wall \
    -Wextra \
    -O2 \
    -I/usr/local/include

LDFLAGS = \
    -L/usr/local/lib64 \
    -Wl,-rpath,/usr/local/lib64 \
    -lssl \
    -lcrypto

TARGET = tls_client

SRC = tls_client.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)