# Workglen DNS client

First-party, bounded asynchronous DNS client for Workglen's existing needs.
Uses Pratique nonblocking sockets, shared timers, OS randomness and first-party
Unicode IDNA normalization. It queries configured recursive resolvers over UDP with
TCP fallback for truncated answers. No new external crate is introduced.

Supported records: A, AAAA, CNAME, MX (including null MX), TXT (preserving
individual chunks), and PTR. SOA data is parsed for negative caching. The
resolver validates transaction/question/owner relationships, compression,
record lengths and alias loops. DNS packet and alias work is bounded; futures
can be cancelled by the application's overall timeout.

`Config::new` accepts resolver socket addresses; defaults are two attempts,
three seconds per attempt/server, 256 cache entries and 256 live/pending sockets.
`Config::system`
reads up to three nameservers from `/etc/resolv.conf`. `Resolver::new`
enforces at most eight servers, four attempts, a 30-second attempt timeout
and 4,096 cache entries; `max_sockets` must be in 1..=4096. An empty server list
is rejected during resolver construction. Socket capacity exhaustion fails immediately.
One timeout spans UDP and the complete TCP fallback. Cancellation closes owned
sockets and releases their shared budget. See NATIVE-ASYNC-DNS.md at the root
for the 2 ms readiness polling design and platform validation limits.

Successful answers expire at the shortest data/CNAME TTL, capped at one day.
NXDOMAIN and NODATA are distinct `NoRecords` errors; negative caching requires
an enclosing SOA and is capped at three hours. TTL zero is never cached.
Temporary failures are never negative-cache entries. The cache is bounded
and evicts the least recently used entry. Simultaneous misses are independent.

This crate does not offer recursive-server operation, DNSSEC validation, DoH,
DoT, search suffix expansion or the full Hickory API. It never trusts an AD bit
as proof of validation. `lookup_ip` preserves Workglen's IPv4-first fallback
to IPv6 when no IPv4 records exist. Explicit record APIs allow both families.

Run `cargo test --offline --locked -p workglen-dns` after preparing the locked
dependencies. Tests use packet fixtures and synthetic loopback UDP/TCP peers.
See the repository's NATIVE-DNS-URL-AUTH.md for integration and review limits.

## Endpoint health

Validated exchanges supply passive endpoint health. Failed endpoints are tried
after healthy endpoints for 2, 4, 8, 16 and then 32 seconds; success resets the
backoff. Cooldown expiry restores configured ordering so a recovered endpoint
can be probed. Valid NXDOMAIN/NODATA answers are not endpoint failures. Existing
timeout, attempt and socket limits remain in force; all configured endpoints
remain available if preferred endpoints also fail. No public fallback or active
background probe is added. Use independent recursors or a per-node recursor.
The application's explicit `dns_server` selects one address; omit it to use
multiple OS resolver entries. One load-balancer VIP is still one endpoint.
