# Native DNS transport and Tokio removal

DEPS-17, October 26, 2026: Tokio and its seven exclusive support package versions
are removed. There are 33 external package versions, five direct external crates
and 40 lockfile entries including seven first-party packages. No registry package
was added, upgraded or changed in checksum. See the current dependency catalog
and `validation/0.8-native-tokio-inventory.json` for exact versions.

## Pratique boundary

Pratique already supplied `block_on`, shared timer futures, `timeout`/`timeout_at`
and async I/O traits. The new reusable additions are cooperative `yield_now` and
bounded nonblocking UDP/TCP sockets in `pratique::asyncio::socket`. Workglen DNS
uses these directly; authentication and routing use the existing executor and
timeout futures. DNS wire handling, resolver selection, retries, cache semantics,
IDNA, authentication and routing policy remain Workglen responsibilities.

`SocketBudget` shares an atomic capacity limit across clones and counts pending
TCP connects as well as open UDP/TCP sockets. Exhaustion fails immediately with
`WouldBlock`, without a task queue. DNS defaults to 256 sockets per resolver and
validates `Config.max_sockets` in 1..=4096. Dropping the owning operation closes its
socket and releases capacity; no detached worker or queued write outlives it.
UDP is dropped before TCP fallback so a limit of one supports a complete attempt.

Every I/O operation yields cooperatively; blocked operations retry readiness
after 2 ms through the existing shared timer. There is no thread per socket,
blocking connect disguised as async, or external runtime. This small polling
implementation trades some readiness latency and wakeups for simplicity; it is
not a full Tokio API, epoll/kqueue reactor or a measured performance improvement.
Like the existing executor, it cannot preempt synchronous CPU work.

One absolute attempt timeout spans UDP, TCP connect, request/response length
prefixes and the whole response payload. Existing retry/attempt bounds and the
outer routing/authentication timeout remain active. Continuous wrong-ID traffic
cannot monopolize polling; trickling cannot restart the attempt deadline.
Cancelled or failed lookups do not poison the DNS cache.

## Platforms and upstream tracking

Nonblocking TCP connect uses a small documented OS boundary on Linux and macOS.
Other platforms return `Unsupported`. Linux x86-64 is exercised here; macOS still
needs native compile/runtime validation before release to that host. No host
configuration, key, service or stored data has been changed.

`PRATIQUE-UPSTREAM.md` and `upstream/pratique/` track the exact additions separately
from the earlier crypto work. Two patches, exact preimage/postimage hashes,
baseline provenance, tests and a non-mutating verifier prepare the GitLab update.
No GitLab repository has been pushed or merged. Reused executor/timer APIs are
explicitly distinguished from newly added code. Pratique has zero external crates.

## Reproduce

```sh
python3 tools/check-native-replacements.py
python3 tools/check-pratique-additions.py --output /tmp/pratique-check
python3 upstream/pratique/verify.py --checkout /path/to/pinned-pratique --vendor vendor/pratique
python3 tools/check-dependency-reduction.py --baseline-zip /path/to/workglen-0.8.0-native-toml-source.zip
```

The first command includes all ten reusable socket tests, twelve native DNS
tests and the real SPF/DMARC shared-deadline regression, plus prior application,
Unicode/MIME/TOML and loopback checks. The standalone harness checks Pratique's
pure feature boundary, zero registry dependencies, new tests and new-module lint.
The patch verifier works entirely in a temporary directory. All fixtures are
synthetic/local; no live DNS, provider, production load or security audit is claimed.

The retired mail-auth oracle still mentions Tokio because it compiles against
the historical source checkpoint in an isolated development harness. It is not
part of the current production, workspace-test or platform dependency graph.
