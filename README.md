# DNS Benchmark

A GTK 4 desktop app (C++20, gtkmm-4.0) that finds the fastest DNS resolver for
your connection. It benchmarks your system's configured DNS servers, well-known
public resolvers and any servers you add, over four transports:

| Protocol | Port | Notes |
|---|---|---|
| UDP | 53 | classic DNS, new random source port per query |
| TCP | 53 | one connection per server, reused between lookups |
| DoT | 853 | DNS-over-TLS (RFC 7858), certificate verified |
| DoH | 443 | DNS-over-HTTPS (RFC 8484), HTTP/2 with HTTP/1.1 fallback |

## Build

```sh
sudo apt install build-essential pkg-config libgtkmm-4.0-dev libssl-dev   # see `make deps`
make            # ./dns-benchmark (GUI)
make test       # unit tests
make cli        # ./dns-benchmark-cli, a GTK-free build of the command-line mode
```

### Launching

Run `./dns-benchmark` or `make run` from a terminal. GNOME Files won't start compiled
programs on double-click, so to get a desktop launcher:

```sh
make install-desktop     # adds "DNS Benchmark" to Activities / the app grid (this build)
make uninstall-desktop   # removes it again
sudo make install        # or install system-wide under /usr/local, launcher included
```

## Using it

1. **Servers**: the list starts with the machine's resolvers (from `/etc/resolv.conf`,
   plus the real upstreams behind systemd-resolved) and the public resolvers
   Cloudflare 1.1.1.1 / 1.0.0.1 / 1.1.1.3, Google 8.8.8.8 / 8.8.4.4,
   Quad9 9.9.9.9 / 149.112.112.112 and OpenDNS. Untick a row to skip it.
2. **Add your own**: enter an IP address and, optionally, a DoT hostname and DoH URL
   (for example `94.140.14.14`, `dns.adguard-dns.com`,
   `https://dns.adguard-dns.com/dns-query`). Custom servers are saved to
   `~/.config/dns-benchmark/servers.conf`.
3. **Settings**:
   - *Lookups* (default 50): lookups per protocol for each server.
   - *Interval* (default 1000 ms): the minimum gap between two lookups sent to the same
     server, across all protocols. The default means at most one lookup per server per
     second.
   - *Timeout*: how long a lookup can take before it counts as failed.
4. Press **Start**. Servers are tested in parallel, and the list re-sorts itself
   fastest-first as results come in. Select a row for full statistics.

## How it measures

- **Ranking**: by median latency, using each server's fastest protocol by default (or one
  protocol you pick under *Rank by*). Servers that lose more than 10% of lookups sort
  after all reliable ones.
- **Cached vs. uncached**: lookups alternate between a popular domain (usually already
  cached by the resolver) and a random subdomain of it, which forces the resolver to
  recurse. Both medians are shown in the details pane.
- **Fairness between protocols**: the protocol order rotates every round and each
  protocol queries a different name. That way no protocol warms the resolver's cache for
  the others.
- **Connection setup**: TCP, DoT and DoH keep one connection open per server, as real
  stub resolvers do. Handshake time is reported separately ("connect") and isn't
  counted in lookup latency.
- **Direct connections**: DoT and DoH connect straight to the listed IP address. The
  hostname is only used for TLS SNI, the certificate check and the HTTP authority.
- **What counts as an answer**: NOERROR and NXDOMAIN. SERVFAIL, REFUSED, timeouts and
  replies that don't match the query count as failures.

## Command-line mode

```sh
./dns-benchmark --cli -n 20 -i 1000 -p udp,dot,doh
./dns-benchmark --cli --only -s 94.140.14.14,dns.adguard-dns.com,https://dns.adguard-dns.com/dns-query -v
```

`--cli -h` lists all options. `-v` prints every lookup with a timestamp.

## Layout

```
src/dns_message.*  DNS wire format (queries, reply validation)
src/net.*, tls.*   non-blocking sockets and OpenSSL TLS streams
src/transport.*    UDP / TCP / DoT / DoH (HTTP/2 + HTTP/1.1) transports
src/benchmark.*    worker threads, per-server rate limiting, ranking
src/stats.*        median / mean / stddev / loss
src/servers.*      built-in servers, custom-server storage
src/system_dns.*   system resolver discovery
src/cli.*          headless mode
src/main_window.*  GTK 4 user interface
tests/             unit tests (`make test`)
```

## License

MIT. See [LICENSE](LICENSE).
