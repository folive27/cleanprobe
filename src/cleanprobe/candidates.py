"""Candidate list handling: seed files, CIDR expansion, sampling."""

from __future__ import annotations

import ipaddress
import random


def load_seed(path: str) -> list[str]:
    """Read a seed file: one host, CIDR, or hostname per line; '#' comments."""
    targets: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            entry = line.split("#", 1)[0].strip()
            if entry:
                targets.append(entry)
    return targets


def expand(target: str, sample: int | None = None, rng: random.Random | None = None) -> list[str]:
    """Expand one seed entry into concrete host addresses.

    Plain hosts/hostnames pass through; CIDR blocks are enumerated, or
    randomly sampled down to `sample` entries when the block is large.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target]  # hostname or single literal we do not understand - pass through

    if network.num_addresses == 1:
        return [str(network.network_address)]

    if sample is not None and sample < network.num_addresses:
        picker = rng or random.Random()
        chosen = set()
        while len(chosen) < sample:
            chosen.add(int(network.network_address) + picker.randrange(network.num_addresses))
        return [str(ipaddress.ip_address(value)) for value in sorted(chosen)]

    return [str(ip) for ip in network]


def expand_all(targets, max_hosts: int = 4096, sample: int | None = None) -> list[str]:
    """Expand many seed entries, capped at `max_hosts` total addresses."""
    out: list[str] = []
    for target in targets:
        out.extend(expand(target, sample=sample))
        if len(out) >= max_hosts:
            return out[:max_hosts]
    return out
