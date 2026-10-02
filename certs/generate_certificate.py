import subprocess
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parent
CERT_DIR.mkdir(parents=True, exist_ok=True)

OPENSSL = "/usr/local/bin/openssl"
PROVIDER_PATH = "/usr/local/lib64/ossl-modules"
OQS_PROVIDERS = ["-provider-path", PROVIDER_PATH, "-provider", "oqsprovider", "-provider", "default"]

configs = [
    {
        "name": "classical",
        "key": "classical.key",
        "cert": "classical.crt",
        "cmd": [OPENSSL, "req", "-x509", "-new", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-keyout", str(CERT_DIR / "classical.key"),
                "-out", str(CERT_DIR / "classical.crt"),
                "-nodes", "-days", "365", "-subj", "/CN=localhost"]
    },
    {
        "name": "mlkem_mldsa",
        "key": "mldsa.key",
        "cert": "mldsa.crt",
        "cmd": [OPENSSL, "req", "-x509", "-new", "-newkey", "mldsa65"] + OQS_PROVIDERS + [
                "-keyout", str(CERT_DIR / "mldsa.key"),
                "-out", str(CERT_DIR / "mldsa.crt"),
                "-nodes", "-days", "365", "-subj", "/CN=localhost"],
        "fallback_alg": "dilithium3"
    },
    {
        "name": "mlkem_slhdsa",
        "key": "slhdsa.key",
        "cert": "slhdsa.crt",
        "cmd": [OPENSSL, "req", "-x509", "-new", "-newkey", "slhdsa128s"] + OQS_PROVIDERS + [
                "-keyout", str(CERT_DIR / "slhdsa.key"),
                "-out", str(CERT_DIR / "slhdsa.crt"),
                "-nodes", "-days", "365", "-subj", "/CN=localhost"],
        "fallback_alg": "sphincsshake128s"
    },
    {
        "name": "hybrid",
        "key": "hybrid.key",
        "cert": "hybrid.crt",
        "cmd": [OPENSSL, "req", "-x509", "-new", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-keyout", str(CERT_DIR / "hybrid.key"),
                "-out", str(CERT_DIR / "hybrid.crt"),
                "-nodes", "-days", "365", "-subj", "/CN=localhost"]
    }
]

for cfg in configs:
    print(f"Generating {cfg['name']}...")
    try:
        subprocess.run(cfg["cmd"], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        if "fallback_alg" in cfg:
            fallback_cmd = list(cfg["cmd"])
            fallback_cmd[fallback_cmd.index(fallback_cmd[5])] = cfg["fallback_alg"]
            subprocess.run(fallback_cmd, check=True)
        else:
            raise

print(f"Generated certificates in: {CERT_DIR}")