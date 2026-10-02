#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys

from config import (
    CONFIGS,
    CERT_DIR,
    OPENSSL,
    PROVIDER_PATH,
    SERVER_PORT,
    get_runtime_env,
)


def start_server(config_name: str):

    if config_name not in CONFIGS:
        print(f"Unknown configuration: {config_name}")
        sys.exit(1)

    cfg = CONFIGS[config_name]

    cert = CERT_DIR / cfg["cert"]
    key = CERT_DIR / cfg["key"]

    if not cert.exists():
        print(f"Certificate not found: {cert}")
        sys.exit(1)

    if not key.exists():
        print(f"Key not found: {key}")
        sys.exit(1)

    command = [
        OPENSSL,
        "s_server",

        "-provider-path",
        PROVIDER_PATH,

        "-provider",
        "oqsprovider",

        "-provider",
        "default",

        "-accept",
        str(SERVER_PORT),

        "-cert",
        str(cert),

        "-key",
        str(key),

        "-groups",
        cfg["group"],

        "-tls1_3",

        "-www",
    ]

    print("\n===========================================")
    print("      PQC TLS 1.3 Test Server")
    print("===========================================")
    print(f"Configuration : {config_name}")
    print(f"Display Name  : {cfg['display']}")
    print(f"TLS Group     : {cfg['group']}")
    print(f"Certificate   : {cert.name}")
    print(f"Key           : {key.name}")
    print(f"Port          : {SERVER_PORT}")
    print("===========================================")
    print("Press Ctrl+C to stop the server.\n")

    process = None

    try:

        process = subprocess.Popen(
            command,
            env=get_runtime_env(),
        )

        process.wait()

    except KeyboardInterrupt:

        print("\nStopping server...")

        if process is not None:

            process.terminate()

            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        print("Server stopped successfully.")

    except Exception as e:

        print(f"\nError: {e}")

        if process is not None:
            process.kill()

        sys.exit(1)


def main():

    parser = argparse.ArgumentParser(
        description="Start PQC TLS 1.3 OpenSSL Server"
    )

    parser.add_argument(
        "config",
        choices=CONFIGS.keys(),
        help="TLS configuration"
    )

    args = parser.parse_args()

    start_server(args.config)


if __name__ == "__main__":
    main()