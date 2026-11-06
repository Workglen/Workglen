# Mail Security Ubuntu/systemd campaign

This campaign turns the remaining target-host acceptance/upgrade work into a
repeatable evidence run. It is intentionally limited to a disposable Ubuntu
gateway configured with reserved `.test` or `.invalid` sender and recipient
domains and a disposable downstream sink. It does not change DNS, MX records,
firewalls, public certificates or provider configuration.

The runner defaults to a read-only plan. It refuses a non-Ubuntu host, a host
without a running systemd, non-test addresses, missing files and an existing
evidence directory. Mutation requires both `--execute` and
`--confirm-disposable-host`; execute mode additionally requires root. The only
service the runner intentionally stops is the separately restartable scanner.
It continuously verifies that the ingress/control unit stays active.

## Prepare the disposable host

1. Install the target build and both supplied systemd units using the normal
   gateway installer. Configure a synthetic enabled recipient and a verified
   TLS route to a disposable sink.
2. Set logical message/job capacity and host free-space reserve above the
   cumulative campaign volume plus normal overhead (85k records for the default
   10k/25k/50k sequence). The runner refuses to begin if the receive queue is
   non-empty or the advertised message/job limits cannot hold the existing
   records plus every requested phase.
3. Use a certificate whose identity matches `--smtp-host`, and pass its issuing
   CA file. Keep the management listener private. Put the test administrator
   password in a root-owned mode-0600 file; the runner uses it only to create an
   authenticated HTTPS session and never copies it into evidence.
4. Create a new evidence path for every run. Existing evidence is never
   overwritten.

Run the read-only preflight first:

```sh
python3 tools/gateway-ubuntu-campaign.py \
  --binary /usr/local/bin/workglen \
  --config /etc/workglen-security/security.json \
  --ca-file /etc/workglen-security/test-ca.pem \
  --admin-url https://127.0.0.1:8445 \
  --admin-password-file /root/workglen-test-admin-password \
  --recipient owner@example.test \
  --smtp-host 127.0.0.1 \
  --smtp-port 25 \
  --output /var/tmp/workglen-campaign-plan
```

The plan records Ubuntu/host identity, CPU count, filesystem capacity, binary
hash, selected systemd hardening/resource properties, queue/capacity status and
the proposed 10k/25k/50k workload. It sends no mail and changes no service.

For the two-physical-host campaign, also supply the peer's private Admin origin
and mode-0600 password file:

```sh
  --peer-admin-url https://node-b.test:8445 \
  --peer-admin-password-file /root/node-b-admin-password
```

The plan then records both live statuses and an `ha_readiness` decision covering
cluster/node identity, reciprocal peer membership, protocol overlap, fresh
bidirectional authenticated contact and zero acceptance/state debt. Execute mode
refuses an unhealthy pair and rechecks convergence after every phase. Repeat the
campaign with the other host as the SMTP target; see
[MAIL-SECURITY-HA-ACTIVATION.md](MAIL-SECURITY-HA-ACTIVATION.md).

After reviewing that file on a disposable host, run the scanner-replacement
campaign:

```sh
sudo python3 tools/gateway-ubuntu-campaign.py \
  --execute --confirm-disposable-host \
  --binary /usr/local/bin/workglen \
  --config /etc/workglen-security/security.json \
  --ca-file /etc/workglen-security/test-ca.pem \
  --admin-url https://127.0.0.1:8445 \
  --admin-password-file /root/workglen-test-admin-password \
  --recipient owner@example.test \
  --smtp-host 127.0.0.1 \
  --smtp-port 25 \
  --messages 10000,25000,50000 \
  --message-bytes 4096 \
  --message-profile mixed \
  --concurrency 40 \
  --output /var/tmp/workglen-campaign-2026-11-04
```

`--message-profile mixed` deterministically cycles five exact-size variants:
plain text, a benign CSV attachment, a compression-heavy GZIP attachment, a
nested `message/rfc822`, and deliberately malformed base64. The phase evidence
records the profile and accepted count for every variant. The default remains
`text` so existing baseline commands are reproducible. Mixed mode requires at
least 4 KiB messages and uses only generated synthetic content.

Run separate evidence directories at 64 KiB, 1 MiB and near the configured MIME
limit; do not combine them into one claimed rate. Compare two, three and four
scanner workers on the same host. Three workers now means one reserved light
worker and two heavy workers; it is a candidate to validate, not a prescribed
production default.

For an actual package-upgrade rehearsal, supply a reviewed root-owned executable
and repeat `--upgrade-arg=value` for fixed arguments. The runner invokes the
executable directly—never through a shell—while synthetic SMTP load is active
and the scanner is stopped:

```sh
  --upgrade-executable /root/workglen-test-upgrade \
  --upgrade-arg=--package=/root/workglen-test.deb
```

The upgrade driver must not modify test data, DNS or firewall state. It may
replace the package/binary and run the package's ordinary daemon reload. The
gateway ingress service must remain active; scanner start is owned by the
campaign runner.

## Pass conditions and evidence

Each phase passes only when every requested SMTP transaction is accepted, none
is deferred/rejected/unattempted, the ingress unit remains active and the
replacement scanner drains receive depth back to the initial zero baseline.
The phase file records acceptance throughput and p50/p95/p99/mean transaction
latency, the exact accepted profile distribution, bounded failure diagnostics,
queued/drained status, systemd resource properties and whether a package driver
ran. `report.json` states the exact qualification; a scanner stop/start run is
never mislabeled as a package upgrade.

Use the 10k/25k/50k phase files to derive a host-specific starting envelope:

- provision logical message capacity above the largest accepted burst plus
  skew/takeover headroom;
- retain at least 50% headroom above measured service `MemoryPeak` and encrypted
  storage growth, then repeat with representative content;
- set the planning acceptance rate no higher than half the lowest sustained
  phase rate until a soak test proves otherwise;
- size steady state from scanner and downstream drain rate, not the faster
  acceptance burst rate;
- repeat at 1 MiB and near the configured MIME limit with benign, malformed,
  nested and compression-heavy fixtures before archive-heavy production sizing.

This runner does not inject host power loss or physically fill a filesystem.
Those campaigns require separate disposable snapshots/volumes and an operator
runbook. It also does not establish malware-detection efficacy, public relay
safety, real-provider interoperability or multi-host HA.
