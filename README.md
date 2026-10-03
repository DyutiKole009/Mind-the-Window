# Mind the Window: Transport-Layer Implications of Post-Quantum TLS 1.3 across Heterogeneous Access Networks

## Introduction

**Mind the Window** is a packet-level experimental framework for studying the transport-layer implications of Post-Quantum Cryptography (PQC) in TLS 1.3 across heterogeneous access networks.

The framework runs repeated TLS 1.3 handshake experiments using classical, post-quantum, and hybrid cryptographic configurations. It captures the resulting network traffic with `tcpdump`, records experiment metadata, and processes the captured PCAP traces using `tshark` to extract transport- and handshake-level measurements.

### Experimental Workflow

```text
TLS Server
    ↓
TLS Client + tcpdump
    ↓
PCAP traces + experiment metadata
    ↓
PCAP analysis using tshark
    ↓
Transport and TLS handshake metrics
    ↓
results.csv
```

---

## Repository Structure

```text
Mind-the-Window/
│
├── certs/
│   └── generate_certificate.py
│
├── Code/
│   ├── client/
│   │   ├── Makefile
│   │   └── tls_client.c
│   ├── results/          # Runtime output
│   ├── traces/           # Runtime PCAP captures
│   ├── batch_run.sh
│   ├── config.py
│   ├── run_client.py
│   └── run_server.py
│
├── Dataset/
│   ├── results/
│   └── traces/
│
├── analysis/
│   ├── Analysis_Final.ipynb
│   └── pcap_parse.py
│
└── README.md
```

> **Generated files:** `Code/traces/`, and `Code/results/` are runtime/generated directories. The `certs/` directory contains `generate_certificate.py`. Upon running this script, the `certs/` directory will locally store generated certificates/private keys, which should not be committed to the repository.

### Main Components

| Component | Purpose |
|---|---|
| `certs/generate_certificate.py` | Generates self-signed TLS certificates and keys for all configurations |
| `Code/config.py` | Central configuration for paths, server, OpenSSL, TLS groups, certificates, and runtime libraries |
| `Code/run_server.py` | Starts the OpenSSL TLS 1.3 test server |
| `Code/run_client.py` | Runs repeated TLS handshakes and automatically captures traffic using `tcpdump` |
| `Code/client/tls_client.c` | C/OpenSSL TLS client implementation used by `run_client.py` |
| `Code/client/Makefile` | Builds the TLS client executable |
| `Code/batch_run.sh` | Runs multiple 100-iteration experiment sessions |
| `analysis/pcap_parse.py` | Processes captured PCAPs using `tshark` and generates transport/TLS metrics |
| `analysis/Analysis_Final.ipynb` | Notebook for analysis and graphical interpretation of the experimental results |
| `certs/` | Contains certificate generation script and locally generated TLS certificates/keys |
| `Code/traces/` | Stores captured PCAP traces |
| `Code/results/` | Stores experiment metadata and analysis results |

---

# 1. Prerequisites

The framework requires a Linux environment with the following software configured:

- Python 3
- OpenSSL
- `liboqs` / OQS provider
- `tcpdump`
- `tshark` — required for PCAP analysis
- TLS certificates and private keys generated during setup
- `sudo` privileges for packet capture

The implementation expects the OpenSSL installation to be available at:

```text
/usr/local/bin/openssl
```

The OQS provider is expected at:

```text
/usr/local/lib64/ossl-modules
```

The configured library search paths are:

```text
/usr/local/lib64
/usr/local/lib
```

These paths are defined in `Code/config.py`.

### Check the basic tools

```bash
python3 --version
openssl version
tcpdump --version
tshark --version
```

---

# 2. TLS Configurations

The experiments use four TLS configurations defined in `config.py`.

| Configuration | Display | TLS Group | Certificate |
|---|---|---|---|
| `classical` | Classical TLS | `prime256v1` | `classical.crt` |
| `mlkem_mldsa` | ML-KEM-768 + ML-DSA-65 | `mlkem768` | `mldsa.crt` |
| `mlkem_slhdsa` | ML-KEM-768 + SLH-DSA-128s | `mlkem768` | `slhdsa.crt` |
| `hybrid` | Hybrid X25519 + ML-KEM-768 | `X25519MLKEM768` | `hybrid.crt` |

The corresponding private keys are also required.

---

# 3. TLS Certificates

TLS certificates and private keys are **generated locally during setup** and stored in:

```text
certs/
```

This directory is intentionally excluded from version control because it contains generated credentials and private keys.

The server expects the certificate and private key corresponding to the selected TLS configuration to be present before the experiment is started.

### Required Certificate and Key Files

| Configuration | Certificate File | Private Key File | Key Algorithm | Signature Scheme |
|---|---|---|---|---|
| `classical` | `classical.crt` | `classical.key` | `ec` (`prime256v1`) | ECDSA with SHA-256 |
| `mlkem_mldsa` | `mldsa.crt` | `mldsa.key` | `mldsa65` (or `dilithium3`) | ML-DSA-65 |
| `mlkem_slhdsa` | `slhdsa.crt` | `slhdsa.key` | `slhdsa128s` (or `sphincsshake128s`) | SLH-DSA-128s |
| `hybrid` | `hybrid.crt` | `hybrid.key` | `ec` (`prime256v1`) | ECDSA with SHA-256 |

### Certificate Generation

Generate all required certificate and key pairs using the provided script:

```bash
python3 certs/generate_certificate.py
```

This script creates self-signed X.509 certificates and private keys inside the `certs/` directory for each of the four TLS configurations. For post-quantum algorithms, it uses the standardized NIST names (`mldsa65`, `slhdsa128s`) with automated fallback to legacy candidate names (`dilithium3`, `sphincsshake128s`) for older OQS provider builds.

### Certificate Validation

To validate that each generated certificate is properly structured, signed, and contains the expected public key algorithm:

```bash
# Validate Classical Certificate
/usr/local/bin/openssl x509 -in certs/classical.crt -text -noout | grep -E "(Signature Algorithm|Public Key Algorithm|Subject:)"

# Validate ML-DSA Certificate
/usr/local/bin/openssl x509 -provider-path /usr/local/lib64/ossl-modules -provider oqsprovider -provider default -in certs/mldsa.crt -text -noout | grep -E "(Signature Algorithm|Public Key Algorithm|Subject:)"

# Validate SLH-DSA Certificate
/usr/local/bin/openssl x509 -provider-path /usr/local/lib64/ossl-modules -provider oqsprovider -provider default -in certs/slhdsa.crt -text -noout | grep -E "(Signature Algorithm|Public Key Algorithm|Subject:)"

# Validate Hybrid Certificate
/usr/local/bin/openssl x509 -in certs/hybrid.crt -text -noout | grep -E "(Signature Algorithm|Public Key Algorithm|Subject:)"
```

---

# 4. Configuration

The main configuration file is:

```text
Code/config.py
```

It defines the server address and port, default iteration count, OpenSSL/OQS paths, TLS groups, certificate/key mappings, and runtime library paths.

### Server

```python
SERVER_IP = "10.64.32.191"
SERVER_PORT = 4434
```

### Default experiment iterations

```python
ITERATIONS = 100
```

The client also accepts a different iteration count using `-n` or `--iterations`.

### OpenSSL

```python
OPENSSL = "/usr/local/bin/openssl"
PROVIDER_PATH = "/usr/local/lib64/ossl-modules"
```

The runtime environment adds the configured library directories to `LD_LIBRARY_PATH`.

---

# 5. Building the TLS Client

The experiment client is implemented in C using OpenSSL and is located in:

```text
Code/client/
├── Makefile
└── tls_client.c
```

Build the client before running the Python experiment driver:

```bash
cd Code/client
make
```

This produces the `tls_client` executable in `Code/client/`. The executable is invoked by `run_client.py` during the experiments.

If the client has already been built and the executable is present, rebuilding is not required unless the source code or build configuration has changed.

---

# 6. Running the TLS Server

Move into the `Code` directory:

```bash
cd Code
```

Start the server using one of the supported configurations:

```bash
python3 run_server.py <config>
```

### Examples

```bash
python3 run_server.py classical
python3 run_server.py mlkem_mldsa
python3 run_server.py mlkem_slhdsa
python3 run_server.py hybrid
```

The server starts an OpenSSL TLS 1.3 server using the selected TLS group, OQS provider, certificate, and private key on port `4434`.

Keep the server running while the client experiments are executed. Press `Ctrl+C` to stop it.

---

# 7. Running the TLS Client

The client is the primary experiment execution component. It creates experiment directories, starts `tcpdump`, performs the configured TLS connections, captures traffic, records timing/connection information, and stores experiment metadata.

Run the client from the `Code` directory:

```bash
sudo python3 run_client.py <config> \
    --network <network> \
    --isp <isp> \
    --session <session> \
    -n <iterations>
```

### Parameters

| Parameter | Description |
|---|---|
| `config` | TLS configuration: `classical`, `mlkem_mldsa`, `mlkem_slhdsa`, or `hybrid` |
| `--network` | Network environment identifier, such as `wifi` or `ethernet` |
| `--isp` | ISP/network identifier, such as `campus` or `home` |
| `--session` | Name used to identify the experiment session |
| `-n`, `--iterations` | Number of TLS handshake iterations; defaults to `100` |

### Example

```bash
sudo python3 run_client.py mlkem_mldsa \
    --network wifi \
    --isp campus \
    --session 2026-07-week1 \
    -n 100
```

`sudo` is required because the client starts `tcpdump` for packet capture.

---

# 8. PCAP Capture and Experiment Metadata

`run_client.py` automatically starts `tcpdump` for every iteration. The capture is restricted to traffic involving the configured server and TCP port `4434`.

PCAP traces are stored as:

```text
Code/traces/
└── <date>/
    └── <session>/
        └── <network>/
            └── <config>/
                ├── iteration_0001.pcap
                ├── iteration_0002.pcap
                └── ...
```

Experiment metadata is stored as:

```text
Code/results/
└── <date>/
    └── <session>/
        └── <network>/
            └── metadata.csv
```

The metadata records information including timestamp, iteration, TLS configuration, network, ISP, success/failure status, TCP/TLS timing, RTT, negotiated cipher/group, and the PCAP path.

---

# 9. Running Multiple Experiments

The repository includes:

```text
Code/batch_run.sh
```

The script accepts:

```text
<config> <network> <isp> <start> <end>
```

and runs 100 iterations for each batch session.

### Usage

From the `Code` directory:

```bash
./batch_run.sh <config> <network> <isp> <start> <end>
```

### Example

```bash
./batch_run.sh mlkem_mldsa wifi campus 1 10
```

This creates sessions `batch1` through `batch10`, with 100 iterations per session.

---

# 10. PCAP Analysis

The analysis code is located at:

```text
analysis/pcap_parse.py
```

The parser uses **`tshark`** to process the PCAP files referenced by experiment metadata.

From the `Code` directory, run:

```bash
python3 ../analysis/pcap_parse.py --session <session_name>
```

### Example

```bash
python3 ../analysis/pcap_parse.py --session 2026-07-week1
```

The parser locates the session under:

```text
Code/results/<date>/<session>/
```

It processes each network directory containing `metadata.csv` and creates `results.csv` in that directory.

```text
Code/results/
└── <date>/
    └── <session>/
        └── <network>/
            ├── metadata.csv
            └── results.csv
```

### Capture vs Analysis

The project uses two separate packet-processing tools:

```text
tcpdump
   ↓
captures packets and writes .pcap files
   ↓
tshark
   ↓
reads/analyzes the .pcap files
   ↓
transport and TLS measurements
```

---

# 11. Analysis Metrics

The PCAP parser extracts transport- and TLS-level measurements including:

### Transport Metrics

- Total packets
- TCP segments
- Retransmissions
- Total wire bytes
- TCP header overhead
- Handshake data packets
- Handshake ACK-only packets
- Transport flights

### TLS Handshake Metrics

- Handshake bytes
- Handshake flights
- ClientHello size
- ServerHello size
- EncryptedExtensions size
- Certificate size
- CertificateVerify size
- Server Finished size
- Client Finished size
- Total TLS bytes

The parser also prints a formatted summary for each processed configuration.

---

# 12. Complete Experiment and Analysis Workflow

```text
1. Configure the environment and generate certificates
        ↓
2. Start the TLS server
        ↓
3. Run the TLS client
        ↓
4. Client automatically starts tcpdump
        ↓
5. PCAP traces and metadata.csv are stored
        ↓
6. Run pcap_parse.py with the session name
        ↓
7. tshark processes the PCAP traces
        ↓
8. results.csv is generated
```

---

# 13. End-to-End Example

### Terminal 1 — Start Server

```bash
cd Code
python3 run_server.py mlkem_mldsa
```

### Terminal 2 — Run Client

```bash
cd Code

sudo python3 run_client.py mlkem_mldsa \
    --network wifi \
    --isp campus \
    --session 2026-07-week1 \
    -n 100
```

### Run Analysis

After the client experiment completes:

```bash
python3 ../analysis/pcap_parse.py \
    --session 2026-07-week1
```

The analysis processes the captured PCAPs using `tshark` and produces `results.csv`.

---

# 14. Running All TLS Configurations

The same experiment can be repeated for each configuration.

### Classical

```bash
python3 run_server.py classical
```

```bash
sudo python3 run_client.py classical \
    --network wifi \
    --isp campus \
    --session classical-wifi \
    -n 100
```

### ML-KEM + ML-DSA

```bash
python3 run_server.py mlkem_mldsa
```

```bash
sudo python3 run_client.py mlkem_mldsa \
    --network wifi \
    --isp campus \
    --session mlkem-mldsa-wifi \
    -n 100
```

### ML-KEM + SLH-DSA

```bash
python3 run_server.py mlkem_slhdsa
```

```bash
sudo python3 run_client.py mlkem_slhdsa \
    --network wifi \
    --isp campus \
    --session mlkem-slhdsa-wifi \
    -n 100
```

### Hybrid

```bash
python3 run_server.py hybrid
```

```bash
sudo python3 run_client.py hybrid \
    --network wifi \
    --isp campus \
    --session hybrid-wifi \
    -n 100
```

The server and client should use the same TLS configuration for an experiment.

---

# 15. Data Organization

The runtime data is organized by date, session, network, and TLS configuration.

### PCAP traces

```text
Code/traces/
└── YYYY-MM-DD/
    └── session/
        └── network/
            └── configuration/
                ├── iteration_0001.pcap
                ├── iteration_0002.pcap
                └── ...
```

### Experiment metadata and analysis results

```text
Code/results/
└── YYYY-MM-DD/
    └── session/
        └── network/
            ├── metadata.csv
            └── results.csv
```

---

# 16. Final Analysis Notebook

The repository also contains:

```text
analysis/Analysis_Final.ipynb
```

This notebook is used for further analysis, visualization, and interpretation of the experimental results after the PCAP-processing stage.

The general workflow is:

```text
PCAP traces
    ↓
analysis/pcap_parse.py
    ↓
results.csv
    ↓
analysis/Analysis_Final.ipynb
    ↓
Final analysis and visualization
```

---

# 17. Reproducibility

For reproducible experiments, record:

- Date of experiment
- TLS configuration
- Network environment
- ISP/network identifier
- Session name
- Number of iterations
- OpenSSL version
- OQS provider version
- System/network environment

The same experiment can then be repeated using the corresponding configuration and session parameters.

---

# 18. Troubleshooting

### `tshark` not found

Verify that `tshark` is installed and available:

```bash
tshark --version
```

### Certificate not found

Verify that the locally generated certificate and private key exist under:

```text
certs/
```

Run `python3 certs/generate_certificate.py` to generate missing certificates.

### OQS provider not found

Verify the configured provider directory:

```text
/usr/local/lib64/ossl-modules
```

### OpenSSL not found

Verify:

```bash
/usr/local/bin/openssl version
```

### Client cannot capture packets

Run the client with `sudo`:

```bash
sudo python3 run_client.py ...
```

### Session not found during analysis

Make sure the experiment has completed and the session exists under:

```text
Code/results/<date>/<session>/
```

Then run:

```bash
python3 ../analysis/pcap_parse.py --session <session>
```

---

# 19. Quick Reference

### Build the TLS client

```bash
cd Code/client
make
```

### Start server

```bash
cd Code
python3 run_server.py <config>
```

### Run client

```bash
sudo python3 run_client.py <config> \
    --network <network> \
    --isp <isp> \
    --session <session> \
    -n 100
```

### Run batch experiments

```bash
./batch_run.sh <config> <network> <isp> <start> <end>
```

### Analyze a session

```bash
python3 ../analysis/pcap_parse.py --session <session>
```

### Supported configurations

```text
classical
mlkem_mldsa
mlkem_slhdsa
hybrid
```

---

## Summary

**Mind the Window** provides a reproducible experimental workflow for evaluating the transport-layer behavior of classical, post-quantum, and hybrid TLS 1.3 configurations.

The framework combines:

- OpenSSL TLS 1.3
- OQS provider
- Classical and PQC/hybrid TLS configurations
- Automated packet capture using `tcpdump`
- PCAP processing using `tshark`
- Experiment metadata collection
- Transport-level and TLS handshake-level measurements
- Batch experiment execution

The primary workflow is:

```text
Configure
   ↓
Generate certificates locally
   ↓
Start server
   ↓
Run client
   ↓
Capture PCAPs with tcpdump
   ↓
Analyze PCAPs with tshark
   ↓
Generate results.csv
```
