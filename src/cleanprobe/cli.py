"""Command line interface for cleanprobe."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .candidates import expand_all, load_seed
from .links import parse_file, parse_vless
from .probe import probe_endpoint, probe_many


def _cmd_scan(args: argparse.Namespace) -> int:
    targets = expand_all(load_seed(args.seed), max_hosts=args.max_hosts, sample=args.sample)
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    snis = [s.strip() for s in args.sni.split(",") if s.strip()]
    combos = [(host, port, sni) for host in targets for port in ports for sni in snis]

    print(f"scanning {len(combos)} probe(s): {len(targets)} host(s) x {len(ports)} port(s) x {len(snis)} sni(s)")
    results = probe_many(combos, workers=args.workers, timeout=args.timeout)

    hits = [r for r in results if r.is_ok()]
    shown = hits if args.only_ok else results
    for r in sorted(shown, key=lambda r: (r.status, r.host)):
        rtt = f"{r.rtt_ms:.0f}ms" if r.rtt_ms is not None else "-"
        tls = "tls13" if r.tls13 else "tls?"
        print(f"  {r.label():<24} {r.host}:{r.port} sni={r.sni} {rtt:>7} {tls if r.is_ok() else ''}".rstrip())

    ok_count = sum(1 for r in results if r.is_ok())
    print(f"done: {ok_count} accepted / {len(results)} probes")

    if args.json_out:
        payload = [
            {
                "host": r.host, "port": r.port, "sni": r.sni, "status": r.status,
                "alert": r.alert, "tls13": r.tls13, "rtt_ms": r.rtt_ms, "detail": r.detail,
            }
            for r in results
        ]
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        print(f"json written: {args.json_out}")
    return 0 if ok_count else 1


def _cmd_probe(args: argparse.Namespace) -> int:
    r = probe_endpoint(args.host, args.port, args.sni, timeout=args.timeout)
    rtt = f"{r.rtt_ms:.0f}ms" if r.rtt_ms is not None else "-"
    print(f"{r.label()}  {r.host}:{r.port} sni={r.sni}  {rtt}  {r.detail}".rstrip())
    if args.json_out:
        payload = {
            "host": r.host, "port": r.port, "sni": r.sni, "status": r.status,
            "alert": r.alert, "tls13": r.tls13, "rtt_ms": r.rtt_ms, "detail": r.detail,
        }
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        print(f"json written: {args.json_out}")
    return 0 if r.is_ok() else 1


def _cmd_check(args: argparse.Namespace) -> int:
    infos = parse_file(args.file)
    bad = 0
    for info in infos:
        state = "ok" if info.ok else "invalid"
        line = f"{state:<7} {info.host}:{info.port} sni={info.sni or '-'}"
        if info.errors:
            line += "  errors: " + "; ".join(info.errors)
        if info.warnings:
            line += "  warnings: " + "; ".join(info.warnings)
        print(line)
        if args.live and info.ok:
            r = probe_endpoint(info.host, info.port, info.sni or info.host, timeout=args.timeout)
            print(f"        live: {r.label()}")
        if not info.ok:
            bad += 1
    print(f"{len(infos) - bad}/{len(infos)} link(s) valid")
    return 0 if infos and not bad else 1


def _cmd_selftest(args: argparse.Namespace) -> int:
    from .selftest import run_selftest

    return run_selftest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cleanprobe", description="TLS endpoint prober and VLESS link validator")
    parser.add_argument("--version", action="version", version=f"cleanprobe {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="probe candidate hosts for TLS handshake acceptance")
    p_scan.add_argument("--seed", required=True, help="file with hosts/CIDRs to probe")
    p_scan.add_argument("--sni", required=True, help="comma-separated server names")
    p_scan.add_argument("--ports", default="443", help="comma-separated ports (default 443)")
    p_scan.add_argument("--workers", type=int, default=32)
    p_scan.add_argument("--timeout", type=float, default=4.0)
    p_scan.add_argument("--sample", type=int, help="random sample size per CIDR block")
    p_scan.add_argument("--max-hosts", type=int, default=4096)
    p_scan.add_argument("--only-ok", action="store_true", help="print only accepted endpoints")
    p_scan.add_argument("--json", dest="json_out", help="write full results as JSON")
    p_scan.set_defaults(func=_cmd_scan)

    p_probe = sub.add_parser("probe", help="probe a single endpoint")
    p_probe.add_argument("host")
    p_probe.add_argument("port", type=int)
    p_probe.add_argument("--sni", required=True)
    p_probe.add_argument("--timeout", type=float, default=4.0)
    p_probe.add_argument("--json", dest="json_out", help="write the result as JSON")
    p_probe.set_defaults(func=_cmd_probe)

    p_check = sub.add_parser("check", help="validate vless:// links from a file")
    p_check.add_argument("file")
    p_check.add_argument("--live", action="store_true", help="also probe each valid link's endpoint")
    p_check.add_argument("--timeout", type=float, default=4.0)
    p_check.set_defaults(func=_cmd_check)

    p_self = sub.add_parser("selftest", help="end-to-end check on loopback (no external traffic)")
    p_self.set_defaults(func=_cmd_selftest)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
