"""Minimal TLS 1.3 ClientHello builder and response classifier.

Written from public specifications only:
  * RFC 8446 - TLS 1.3
  * RFC 6066 - TLS Extensions (server_name)
  * RFC 7301 - ALPN
  * RFC 7748 - X25519

Purpose: send a well-formed ClientHello for a chosen server name and read
the first response record. This distinguishes endpoints that accept a
server name (ServerHello) from strict ones that reject it (Alert, e.g.
handshake_failure=40) or never answer (timeout) - the key signal when
picking or diagnosing a REALITY destination / candidate endpoint.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

LEGACY_VERSION = 0x0303
TLS13_VERSION = 0x0304
GROUP_X25519 = 0x001D

CIPHER_SUITES = (0x1301, 0x1302, 0x1303)  # AES-128-GCM, AES-256-GCM, CHACHA20
SIGNATURE_ALGORITHMS = (0x0403, 0x0804, 0x0807)  # ecdsa_p256_sha256, rsa_pss_rsae_sha256, ed25519
DEFAULT_ALPN = ("h2", "http/1.1")

RECORD_HANDSHAKE = 22
RECORD_ALERT = 21
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2

ALERT_NAMES = {
    40: "handshake_failure",
    70: "protocol_version",
    80: "internal_error",
    86: "inappropriate_fallback",
    112: "unrecognized_name",
    113: "bad_certificate",
}


def _u8(v: int) -> bytes:
    return struct.pack(">B", v)


def _u16(v: int) -> bytes:
    return struct.pack(">H", v)


def _u24(v: int) -> bytes:
    return struct.pack(">I", v)[1:]


def _vec8(data: bytes) -> bytes:
    return _u8(len(data)) + data


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _extension(ext_type: int, payload: bytes) -> bytes:
    return _u16(ext_type) + _vec16(payload)


def _x25519_public(private_key: X25519PrivateKey) -> bytes:
    pub = private_key.public_key()
    if hasattr(pub, "public_bytes_raw"):
        return pub.public_bytes_raw()
    from cryptography.hazmat.primitives import serialization

    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def build_client_hello(
    server_name: str,
    *,
    random: bytes | None = None,
    session_id: bytes | None = None,
    private_key: X25519PrivateKey | None = None,
    alpn: tuple[str, ...] = DEFAULT_ALPN,
) -> bytes:
    """Return one TLS record containing a TLS 1.3 ClientHello for `server_name`.

    Optional arguments make the message deterministic for tests.
    """
    rnd = os.urandom(32) if random is None else random
    sid = os.urandom(32) if session_id is None else session_id
    key = X25519PrivateKey.generate() if private_key is None else private_key
    pubkey = _x25519_public(key)

    ext = b""
    # RFC 6066 - server_name (entry: name_type=host_name(0) + name)
    name = server_name.encode("ascii", "idna")
    ext += _extension(0x0000, _vec16(_u8(0) + _vec16(name)))
    # RFC 7301 - ALPN
    alpn_list = b"".join(_vec8(p.encode()) for p in alpn)
    ext += _extension(0x0010, _vec16(alpn_list))
    # supported_groups: x25519 only (what REALITY-style stacks negotiate)
    ext += _extension(0x000A, _vec16(_u16(GROUP_X25519)))
    # key_share (list<0..2^16-1> of KeyShareEntry)
    ext += _extension(0x0033, _vec16(_u16(GROUP_X25519) + _vec16(pubkey)))
    # supported_versions: single version, 1-byte length prefix
    ext += _extension(0x002B, _vec8(_u16(TLS13_VERSION)))
    # signature_algorithms
    ext += _extension(0x000D, _vec16(b"".join(_u16(s) for s in SIGNATURE_ALGORITHMS)))
    # psk_key_exchange_modes: psk_dhe_ke
    ext += _extension(0x002D, _vec8(_u8(1)))

    body = (
        _u16(LEGACY_VERSION)
        + rnd
        + _vec8(sid)
        + _vec16(b"".join(_u16(c) for c in CIPHER_SUITES))
        + _vec8(_u8(0))  # null compression
        + _vec16(ext)
    )
    handshake = _u8(HS_CLIENT_HELLO) + _u24(len(body)) + body
    return _u8(RECORD_HANDSHAKE) + _u16(LEGACY_VERSION) + _u16(len(handshake)) + handshake


@dataclass
class ProbeResult:
    status: str  # ok | alert | timeout | refused | reset | error | unexpected
    alert: int | None = None
    tls13: bool | None = None
    rtt_ms: float | None = None
    detail: str = ""
    host: str = ""
    port: int = 0
    sni: str = ""

    def is_ok(self) -> bool:
        return self.status == "ok"

    def label(self) -> str:
        if self.status == "alert" and self.alert is not None:
            name = ALERT_NAMES.get(self.alert, "")
            return f"alert({self.alert}{' ' + name if name else ''})"
        return self.status


def _read_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionResetError("peer closed connection")
        buf += chunk
    return buf


def read_record(sock: socket.socket) -> tuple[int, bytes]:
    """Read one TLS record; returns (content_type, payload)."""
    header = _read_exact(sock, 5)
    content_type = header[0]
    length = struct.unpack(">H", header[3:5])[0]
    payload = _read_exact(sock, length) if length else b""
    return content_type, payload


def _server_hello_is_tls13(payload: bytes) -> bool | None:
    """Best-effort check for supported_versions=0x0304 inside a ServerHello."""
    try:
        if payload[0] != HS_SERVER_HELLO:
            return None
        pos = 4 + 2 + 32  # handshake header + legacy_version + random
        sid_len = payload[pos]
        pos += 1 + sid_len + 2 + 1  # session id echo + cipher suite + compression
        ext_len = struct.unpack(">H", payload[pos : pos + 2])[0]
        pos += 2
        end = pos + ext_len
        while pos + 4 <= end:
            etype, elen = struct.unpack(">HH", payload[pos : pos + 4])
            pos += 4
            if etype == 0x002B and elen >= 2:
                return struct.unpack(">H", payload[pos : pos + 2])[0] == TLS13_VERSION
            pos += elen
    except (IndexError, struct.error):
        return None
    return None


def classify_response(sock: socket.socket) -> ProbeResult:
    """Classify the endpoint's first response record."""
    try:
        content_type, payload = read_record(sock)
    except socket.timeout:
        return ProbeResult("timeout")
    except ConnectionResetError:
        return ProbeResult("reset")
    except OSError as exc:
        return ProbeResult("error", detail=str(exc))

    if content_type == RECORD_ALERT and len(payload) >= 2:
        return ProbeResult("alert", alert=payload[1], detail="server rejected the handshake")
    if content_type == RECORD_HANDSHAKE and payload and payload[0] == HS_SERVER_HELLO:
        return ProbeResult("ok", tls13=_server_hello_is_tls13(payload))
    return ProbeResult("unexpected", detail=f"unexpected record type {content_type}")
