"""Loopback-only CLI integration check.

Starts a real TLS 1.3 server on 127.0.0.1 and runs the actual CLI
(scan + check --live) against it, then a closed port for the refused
path. No external traffic.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / ".venv" / "bin" / "cleanprobe"


def _cert(tmp):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "loopback")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    c, k = Path(tmp) / "c.pem", Path(tmp) / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(c), str(k)


def main() -> int:
    fails = 0
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = _cert(tmp)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        stop = threading.Event()

        def serve():
            srv.settimeout(0.5)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    ctx.wrap_socket(conn, server_side=True).close()
                except Exception:
                    pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        seed = Path(tmp) / "seed.txt"
        seed.write_text(f"127.0.0.1\n# also a closed port\n")
        out = subprocess.run(
            [str(CLI), "scan", "--seed", str(seed), "--sni", "loopback.test", "--ports", str(port)],
            capture_output=True, text=True,
        )
        print("--- scan stdout ---"); print(out.stdout.strip())
        if "ok" not in out.stdout or str(port) not in out.stdout:
            fails += 1; print("FAIL scan did not report ok")

        links = Path(tmp) / "links.txt"
        links.write_text(
            f"vless://6f9b0c8e-1a2b-4c3d-8e5f-0a1b2c3d4e5f@127.0.0.1:{port}"
            "?security=reality&pbk=Uu6N5m8Qe1s0VdT7wZbY3cXaR4pLkN2hJfG9dSmEoQ0&sni=loopback.test#loop\n"
        )
        out2 = subprocess.run([str(CLI), "check", str(links), "--live"], capture_output=True, text=True)
        print("--- check --live stdout ---"); print(out2.stdout.strip())
        if "live: ok" not in out2.stdout:
            fails += 1; print("FAIL check --live did not report live ok")

        jf = Path(tmp) / "r.json"
        out3 = subprocess.run(
            [str(CLI), "probe", "127.0.0.1", str(port), "--sni", "loopback.test", "--json", str(jf)],
            capture_output=True, text=True,
        )
        print("--- probe --json stdout ---"); print(out3.stdout.strip())
        import json
        data = json.loads(jf.read_text())
        if data.get("status") != "ok" or data.get("tls13") is not True:
            fails += 1; print("FAIL json payload wrong:", data)

        stop.set()
        srv.close()
        t.join(timeout=2)

    print("integration:", "FAIL" if fails else "OK")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
