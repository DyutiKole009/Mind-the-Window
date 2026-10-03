from pathlib import Path
import os

# =====================================================
# Paths
# =====================================================

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

CERT_DIR = REPO_ROOT / "certs"
DATASET_DIR = REPO_ROOT / "Dataset"
TRACE_DIR = DATASET_DIR / "traces"
RESULT_DIR = DATASET_DIR / "results"

# =====================================================
# Server
# =====================================================

SERVER_IP = "10.64.32.191"
SERVER_PORT = 4434

# =====================================================
# Experiment
# =====================================================

ITERATIONS = 100

# =====================================================
# OpenSSL
# =====================================================

OPENSSL = "/usr/local/bin/openssl"

PROVIDER_PATH = "/usr/local/lib64/ossl-modules"

LIBRARY_PATHS = [
    "/usr/local/lib64",
    "/usr/local/lib",
]

# =====================================================
# TLS Configurations
# =====================================================

CONFIGS = {

    "classical": {

        "display": "Classical TLS",

        "group": "prime256v1",

        "cert": "classical.crt",

        "key": "classical.key"

    },

    "mlkem_mldsa": {

        "display": "ML-KEM-768 + ML-DSA-65",

        "group": "mlkem768",

        "cert": "mldsa.crt",

        "key": "mldsa.key"

    },

    "mlkem_slhdsa": {

        "display": "ML-KEM-768 + SLH-DSA-128s",

        "group": "mlkem768",

        "cert": "slhdsa.crt",

        "key": "slhdsa.key"

    },

    "hybrid": {

        "display": "Hybrid X25519 + ML-KEM-768",

        "group": "X25519MLKEM768",

        "cert": "hybrid.crt",

        "key": "hybrid.key"

    }

}

# =====================================================
# Runtime Environment
# =====================================================

def get_runtime_env():
    """
    Returns an environment with the correct OpenSSL
    runtime library search path.
    """

    env = os.environ.copy()

    existing = env.get("LD_LIBRARY_PATH", "")

    prefix = ":".join(LIBRARY_PATHS)

    if existing:
        env["LD_LIBRARY_PATH"] = f"{prefix}:{existing}"
    else:
        env["LD_LIBRARY_PATH"] = prefix

    return env
