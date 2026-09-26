# cleanprobe

Minimal TLS endpoint prober and VLESS/REALITY link validator.

Answers two questions:

* **Which endpoints complete a TLS 1.3 handshake for a given server name?**
  (`cleanprobe scan`) — useful when hunting for REALITY-style destinations
  and clean IPs: a destination that answers a ClientHello for the chosen
  name is a candidate; one that returns `handshake_failure` or nothing is not.
* **Is this set of links well-formed?** (`cleanprobe check`) — validates
  `vless://` links: UUID, port, `security=reality` fields (`sni`, `pbk`
  32-byte key, hex `sid`), and can optionally probe each endpoint.

## Install

```
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

## Usage

```
# probe one endpoint
cleanprobe probe 203.0.113.10 443 --sni cdn.example.net

# scan candidates (seed file: hosts, CIDRs, hostnames - one per line)
cleanprobe scan --seed seeds/example.txt --sni cdn.example.net,www.example.org \
                --ports 443,8443 --workers 64 --sample 200 --json out.json

# validate links
cleanprobe check links.txt --live

# end-to-end check on loopback only (no external traffic)
cleanprobe selftest
```

## Design notes

* The TLS 1.3 ClientHello is built from the RFCs directly (RFC 8446,
  RFC 6066, RFC 7301, RFC 7748) - no TLS stack required client-side;
  only `cryptography` for X25519 key generation.
* Response classification: `ok` (ServerHello), `alert(n)` (rejected,
  e.g. 40 = handshake_failure), `timeout`, `refused`, `reset`.
* `selftest` runs against throwaway loopback servers, including a real
  TLS 1.3 endpoint built with the standard library, an alert(40) server
  and a byte-dribbling server - so the whole pipeline is verifiable
  without sending any external traffic.

## License

MIT (see LICENSE). Independent implementation; written from public
protocol documentation only.
