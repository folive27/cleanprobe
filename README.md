# cleanprobe

A small tool that answers two questions:

1. **Which endpoints work?** It sends a TLS 1.3 handshake for a chosen server
   name (SNI) and reports which IPs accept it. Handy when looking for
   REALITY-style destinations or clean IPs.
2. **Are my links valid?** It checks that a list of `vless://` links is
   well-formed (UUID, port, REALITY fields, ...).

🇮🇷 راهنمای فارسی: [docs/QUICKSTART.fa.md](docs/QUICKSTART.fa.md)

---

## Install (pick one)

### 1. One-line installer (easiest)

```bash
curl -fsSL https://raw.githubusercontent.com/frank0live/cleanprobe/main/install.sh | bash
```

It installs into `~/.cleanprobe`, creates a `cleanprobe` command in
`~/.local/bin`, and tells you if your `PATH` needs a one-line tweak.
**No root needed.** Works with just `python3` + `curl` (git is optional).

### 2. With pip / pipx

```bash
pipx install git+https://github.com/frank0live/cleanprobe
# or
pip install git+https://github.com/frank0live/cleanprobe
```

### 3. From source

```bash
git clone https://github.com/frank0live/cleanprobe
cd cleanprobe
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
```

Requirement: Python 3.9+.

---

## First check (30 seconds)

```bash
cleanprobe selftest
```

Expected last line:

    selftest: 22/22 passed

If you see that, the install is good. The selftest only talks to loopback
(your own machine) — no internet needed, nothing external is touched.

---

## How to use it

### 1) Probe one endpoint

```bash
cleanprobe probe www.cloudflare.com 443 --sni www.cloudflare.com
```

Real output:

    ok  www.cloudflare.com:443 sni=www.cloudflare.com  45ms

### 2) Scan a list of candidates

The seed file — one entry per line (an IP, an IP range, or a hostname):

    # seeds/example.txt
    1.1.1.1
    104.16.0.0/24
    cdn.example.net

Then:

```bash
cleanprobe scan --seed seeds/example.txt --sni www.cloudflare.com --ports 443,8443
```

Real output (small demo run):

    scanning 3 probe(s): 3 host(s) x 1 port(s) x 1 sni(s)
      ok                       1.1.1.1:443 sni=www.cloudflare.com    59ms tls13
      ok                       104.16.132.229:443 sni=www.cloudflare.com    58ms tls13
      timeout                  203.0.113.1:443 sni=www.cloudflare.com  3006ms
    done: 2 accepted / 3 probes

Useful flags:

* `--workers 64` — more parallel connections (faster)
* `--sample 200` — test a random sample from large ranges
* `--only-ok` — show only working endpoints
* `--json out.json` — full results as JSON, for scripts

### 3) Validate links

```bash
cleanprobe check links.txt          # add --live to also probe each endpoint
```

Real output:

    ok      1.1.1.1:443 sni=www.cloudflare.com
    invalid example.com:443 sni=-  errors: uuid is not a valid UUID; security=reality requires sni=; pbk does not decode to a 32-byte public key; sid must be hex, at most 16 chars
    1/2 link(s) valid

---

## Reading the results

| status | meaning |
|---|---|
| `ok` | TLS 1.3 handshake completed for that name — good candidate |
| `alert` | the endpoint answered but refused the name (e.g. `alert 40` = handshake_failure) |
| `timeout` | no answer in time |
| `refused` / `reset` | connection refused or closed by the endpoint |

Note: normally only a name that the target itself serves will be accepted —
that is why choosing the right SNI matters.

## FAQ

* **Do I need root?** No.
* **Does it send my links anywhere?** No. `check` is fully local unless you
  pass `--live`.
* **Where do scan connections go?** Only to the addresses in your seed file.
* **Windows?** Same commands, different paths: use
  `.venv\Scripts\cleanprobe` instead of `.venv/bin/cleanprobe`.
* **How do I uninstall?** `rm -rf ~/.cleanprobe ~/.local/bin/cleanprobe`

## Design notes

* The TLS 1.3 ClientHello is built from the RFCs directly (RFC 8446,
  RFC 6066, RFC 7301, RFC 7748) — no TLS stack required client-side; only
  `cryptography` for X25519 key generation.
* Response classification: `ok` (ServerHello), `alert(n)` (rejected,
  e.g. 40 = handshake_failure), `timeout`, `refused`, `reset`.
* `selftest` runs against throwaway loopback servers, including a real
  TLS 1.3 endpoint built with the standard library, an alert(40) server
  and a byte-dribbling server — so the whole pipeline is verifiable
  without sending any external traffic.

## License

MIT (see LICENSE). Independent implementation; written from public
protocol documentation only.
