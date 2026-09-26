"""End-to-end self-test on loopback only - no external network traffic.

Stands up two throwaway local servers:
  * a real TLS 1.3 endpoint (stdlib ssl + a self-signed cert generated on
    the fly) - must be classified as "ok" with tls13=True;
  * a raw socket that replies with a canned handshake_failure alert -
    must be classified as alert(40).
Also covers the length-parser (fragmented record), link validation and
candidate expansion. Everything binds to 127.0.0.1 on ephemeral ports.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import tempfile
import threading
from pathlib import Path

from .candidates import expand
from .hello import ProbeResult, build_client_hello, classify_response
from .links import parse_vless
from .probe import probe_endpoint


def _self_signed_cert(directory: str) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "loopback")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = Path(directory) / "cert.pem"
    key_path = Path(directory) / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


class _LoopbackServer:
    """One-shot TCP server on 127.0.0.1 that hands the connection to `handler`."""

    def __init__(self, handler):
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            self._handler(conn)
        except Exception:
            pass
        finally:
            conn.close()
            self._sock.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._thread.join(timeout=5)
        try:
            self._sock.close()
        except OSError:
            pass
        return False


def _tls_handler(cert_path: str, key_path: str):
    import ssl

    def handle(conn: socket.socket):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        try:
            ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            pass

    return handle


def _alert_handler(conn: socket.socket):
    conn.recv(4096)  # consume the ClientHello, then reject
    conn.sendall(bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]))  # fatal handshake_failure(40)


def _unexpected_handler(conn: socket.socket):
    conn.recv(4096)
    conn.sendall(bytes([0x99, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00]))


class _ChunkedAlertServer(_LoopbackServer):
    """Variant that dribbles the alert byte-by-byte to exercise the reader loop."""

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            conn.recv(4096)
            for byte in bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]):
                conn.sendall(bytes([byte]))
            conn.close()
        finally:
            self._sock.close()


def _check(name: str, condition: bool, seen: list[str], detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    seen.append(f"{mark} {name}{' - ' + detail if detail and not condition else ''}")


def run_selftest() -> int:
    seen: list[str] = []

    # 1. ClientHello structure (deterministic build).
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    fixed = build_client_hello(
        "example.test",
        random=b"\x07" * 32,
        session_id=b"\x05" * 32,
        private_key=X25519PrivateKey.from_private_bytes(b"\x09" * 32),
    )
    again = build_client_hello(
        "example.test",
        random=b"\x07" * 32,
        session_id=b"\x05" * 32,
        private_key=X25519PrivateKey.from_private_bytes(b"\x09" * 32),
    )
    _check("clienthello deterministic", fixed == again, seen)
    _check("clienthello has server_name", b"example.test" in fixed, seen)
    _check("clienthello advertises tls1.3", b"\x00\x2b\x00\x03\x02\x03\x04" in fixed, seen)
    _check("clienthello record framing", fixed[0] == 22 and int.from_bytes(fixed[3:5], "big") == len(fixed) - 5, seen)

    # 2. A real TLS 1.3 server accepts the hello -> ok / tls13.
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = _self_signed_cert(tmp)
        with _LoopbackServer(_tls_handler(cert, key)) as server:
            result = probe_endpoint("127.0.0.1", server.port, "example.test", timeout=5.0)
        _check("loopback tls13 accepted", result.status == "ok" and result.tls13 is True, seen, result.label())
        _check("loopback result carries target", result.host == "127.0.0.1" and result.sni == "example.test", seen)
        _check("loopback rtt measured", isinstance(result.rtt_ms, float) and result.rtt_ms >= 0, seen)

    # 3. Alert(40) server and an unexpected-record server.
    with _LoopbackServer(_alert_handler) as server:
        result = probe_endpoint("127.0.0.1", server.port, "strict.test", timeout=5.0)
    _check("alert 40 detected", result.status == "alert" and result.alert == 40, seen, result.label())
    _check("alert label human readable", result.label() == "alert(40 handshake_failure)", seen)

    with _LoopbackServer(_unexpected_handler) as server:
        result = probe_endpoint("127.0.0.1", server.port, "odd.test", timeout=5.0)
    _check("unexpected record flagged", result.status == "unexpected", seen, result.label())

    # 4. Refused connection.
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    dead.close()
    result = probe_endpoint("127.0.0.1", dead_port, "closed.test", timeout=2.0)
    _check("refused detected", result.status == "refused", seen, result.label())

    # 5. Fragmented (byte-by-byte) response still parsed.
    with _ChunkedAlertServer(None) as server:
        result = probe_endpoint("127.0.0.1", server.port, "drip.test", timeout=5.0)
    _check("fragmented record parsed", result.status == "alert" and result.alert == 40, seen, result.label())

    # 6. Link validation.
    good = parse_vless(
        "vless://6f9b0c8e-1a2b-4c3d-8e5f-0a1b2c3d4e5f@198.51.100.7:443"
        "?type=tcp&security=reality&pbk=Uu6N5m8Qe1s0VdT7wZbY3cXaR4pLkN2hJfG9dSmEoQ0"
        "&fp=chrome&sni=cdn.example.net&sid=1a2b&spx=%2F&flow=xtls-rprx-vision#node-a"
    )
    _check("valid link accepted", good.ok, seen, "; ".join(good.errors))
    _check("valid link fields", good.host == "198.51.100.7" and good.port == 443 and good.sni == "cdn.example.net", seen)
    short_key = parse_vless("vless://6f9b0c8e-1a2b-4c3d-8e5f-0a1b2c3d4e5f@198.51.100.7:443?security=reality&pbk=AAAA&sni=x.test")
    _check("short pbk rejected", not short_key.ok and any("pbk" in e for e in short_key.errors), seen)
    wrong_scheme = parse_vless("vmess://whatever")
    _check("wrong scheme rejected", not wrong_scheme.ok, seen)
    no_sni = parse_vless("vless://6f9b0c8e-1a2b-4c3d-8e5f-0a1b2c3d4e5f@198.51.100.7:443?security=reality&pbk=Uu6N5m8Qe1s0VdT7wZbY3cXaR4pLkN2hJfG9dSmEoQ0")
    _check("reality without sni rejected", not no_sni.ok, seen)

    # 7. Candidate expansion.
    small = expand("198.51.100.0/30")
    _check("cidr expanded", len(small) == 4 and small[0] == "198.51.100.0", seen, str(small))
    sampled = expand("203.0.113.0/24", sample=5)
    _check("cidr sampled", len(sampled) == 5 and len(set(sampled)) == 5, seen)
    _check("hostname passes through", expand("cdn.example.net") == ["cdn.example.net"], seen)
    _check("single ip passes through", expand("192.0.2.9") == ["192.0.2.9"], seen)

    # 8. Sanity: the sampled addresses belong to the block.
    block = ipaddress.ip_network("203.0.113.0/24")
    _check("sampled addresses in range", all(ipaddress.ip_address(a) in block for a in sampled), seen)

    failures = [line for line in seen if line.startswith("FAIL")]
    for line in seen:
        print(line)
    print(f"selftest: {len(seen) - len(failures)}/{len(seen)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run_selftest())
