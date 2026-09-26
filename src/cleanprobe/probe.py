"""Endpoint probing: TCP connect + ClientHello + response classification."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from .hello import ProbeResult, build_client_hello, classify_response


def probe_endpoint(host: str, port: int, sni: str, timeout: float = 4.0) -> ProbeResult:
    """Probe one endpoint: does it complete a handshake for `sni`?"""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(build_client_hello(sni))
            result = classify_response(sock)
    except ConnectionRefusedError:
        result = ProbeResult("refused")
    except socket.timeout:
        result = ProbeResult("timeout")
    except ConnectionResetError:
        result = ProbeResult("reset")
    except OSError as exc:
        result = ProbeResult("error", detail=str(exc))

    result.host, result.port, result.sni = host, port, sni
    result.rtt_ms = round((time.perf_counter() - started) * 1000, 1)
    return result


def probe_many(items, workers: int = 32, timeout: float = 4.0) -> list[ProbeResult]:
    """Probe a list of (host, port, sni) tuples concurrently."""
    items = list(items)
    if not items:
        return []
    results: list[ProbeResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(probe_endpoint, h, p, s, timeout) for h, p, s in items]
        for future in futures:
            results.append(future.result())
    return results
