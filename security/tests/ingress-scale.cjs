'use strict';

// Release-mode resource wrapper for the ignored Rust ingress scale profile.
// Usage: node security/tests/ingress-scale.cjs [message-counts] [thread-counts] [message-bytes] [drain] [nodes] [node-weights] [replicas]
// Example: node security/tests/ingress-scale.cjs 1000,5000 1,4,16,32 65536 0 3 1,1,1 1
// Optional regression floors/ceilings are supplied through WORKGLEN_INGRESS_SCALE_MIN_ACCEPTS_PER_SECOND,
// WORKGLEN_INGRESS_SCALE_MAX_ACCEPT_P95_MS, WORKGLEN_INGRESS_SCALE_MAX_TAIL_P95_MS and
// WORKGLEN_INGRESS_SCALE_MAX_STATUS_MS. Calibrate them on the target host; no portable default is implied.

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const os = require('node:os');

const counts = (process.argv[2] || '1000').split(',').map(Number);
const threadCounts = (process.argv[3] || '20').split(',').map(Number);
const messageBytes = Number(process.argv[4] || 4096);
const drain = process.argv[5] === '1';
const nodes = Number(process.argv[6] || 1);
const nodeWeights = (process.argv[7] || Array(nodes).fill(1).join(',')).split(',').map(Number);
const replicas = Number(process.argv[8] || 0);
assert(counts.length > 0 && counts.every(value => Number.isInteger(value) && value >= 100 && value <= 100000));
assert(threadCounts.length > 0 && threadCounts.every(value => Number.isInteger(value) && value >= 1 && value <= 100));
assert(Number.isInteger(messageBytes) && messageBytes >= 256 && messageBytes <= 10 * 1024 * 1024);
assert(Number.isInteger(nodes) && nodes >= 1 && nodes <= 8);
assert(nodeWeights.length === nodes && nodeWeights.every(value => Number.isInteger(value) && value >= 1 && value <= 100));
assert(Number.isInteger(replicas) && replicas >= 0 && replicas <= Math.min(2, nodes - 1));
assert(!drain || replicas === 0, 'Replicated finalization/drain is not implemented yet');
assert(counts.every(value => Math.ceil(value / nodes) * messageBytes <= 1024 ** 3), 'Each node must fit the one-GiB content ceiling');

function optionalPositive(name) {
  if (process.env[name] === undefined) return null;
  const value = Number(process.env[name]);
  assert(Number.isFinite(value) && value > 0, `${name} must be a positive number`);
  return value;
}

const thresholds = {
  min_accepts_per_second: optionalPositive('WORKGLEN_INGRESS_SCALE_MIN_ACCEPTS_PER_SECOND'),
  max_accept_p95_ms: optionalPositive('WORKGLEN_INGRESS_SCALE_MAX_ACCEPT_P95_MS'),
  max_tail_p95_ms: optionalPositive('WORKGLEN_INGRESS_SCALE_MAX_TAIL_P95_MS'),
  max_status_ms: optionalPositive('WORKGLEN_INGRESS_SCALE_MAX_STATUS_MS'),
};

const build = childProcess.spawnSync(
  'cargo',
  ['test', '--release', '--no-run', '--message-format=json', 'ingress_backlog_scaling_profile'],
  { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
);
if (build.status !== 0) throw Error(build.stderr || build.stdout);
let executable;
for (const line of build.stdout.split('\n')) {
  if (!line.startsWith('{')) continue;
  const artifact = JSON.parse(line);
  if (
    artifact.reason === 'compiler-artifact'
    && artifact.target?.name === 'workglen_mail'
    && artifact.profile?.test
    && artifact.executable
  ) executable = artifact.executable;
}
assert(executable, 'The Workglen release test executable was not found');

function numberFrom(text, expression) {
  const match = text.match(expression);
  return match ? Number(match[1]) : null;
}

function timedRun(messages, threads) {
  const platform = os.platform();
  const timeArguments = platform === 'darwin' ? ['-l'] : ['-v'];
  timeArguments.push(
    executable,
    'ingress_backlog_scaling_profile',
    '--ignored',
    '--nocapture',
    '--test-threads=1',
  );
  const result = childProcess.spawnSync('/usr/bin/time', timeArguments, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 60 * 60 * 1000,
    env: {
      ...process.env,
      WORKGLEN_INGRESS_SCALE_MESSAGES: String(messages),
      WORKGLEN_INGRESS_SCALE_THREADS: String(threads),
      WORKGLEN_INGRESS_SCALE_MESSAGE_BYTES: String(messageBytes),
      WORKGLEN_INGRESS_SCALE_DRAIN: drain ? '1' : '0',
      WORKGLEN_INGRESS_SCALE_NODES: String(nodes),
      WORKGLEN_INGRESS_SCALE_NODE_WEIGHTS: nodeWeights.join(','),
      WORKGLEN_INGRESS_SCALE_REPLICAS: String(replicas),
    },
  });
  if (result.status !== 0) throw Error(result.error || result.stderr || result.stdout);
  const marker = result.stdout.match(/INGRESS_SCALE (\{[^\n]+\})/);
  assert(marker, result.stdout);
  const profile = JSON.parse(marker[1]);
  let peakRssBytes;
  let userSeconds;
  let systemSeconds;
  let elapsedSeconds;
  if (platform === 'darwin') {
    peakRssBytes = numberFrom(result.stderr, /^\s*(\d+)\s+maximum resident set size$/m);
    const times = result.stderr.match(/^\s*([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys$/m);
    if (times) {
      elapsedSeconds = Number(times[1]);
      userSeconds = Number(times[2]);
      systemSeconds = Number(times[3]);
    }
  } else {
    const peakRssKiB = numberFrom(result.stderr, /Maximum resident set size \(kbytes\):\s*(\d+)/);
    peakRssBytes = peakRssKiB === null ? null : peakRssKiB * 1024;
    userSeconds = numberFrom(result.stderr, /User time \(seconds\):\s*([\d.]+)/);
    systemSeconds = numberFrom(result.stderr, /System time \(seconds\):\s*([\d.]+)/);
    elapsedSeconds = profile.acceptance_ms / 1000 + profile.drain_ms / 1000;
  }
  const mebibyte = 1024 ** 2;
  const peakRssMiB = peakRssBytes === null ? null : peakRssBytes / mebibyte;
  const recommendedMemoryMiB = peakRssMiB === null
    ? null
    : Math.max(256, Math.ceil((peakRssMiB * 1.5) / 128) * 128);
  const aggregateSpoolReserveMiB = Math.ceil(
    (profile.queue_disk_delta_bytes * 1.5) / mebibyte,
  );
  const perNodeSpoolReserveMiB = profile.queue_disk_delta_by_node.map(
    bytes => Math.ceil((bytes * 1.5) / mebibyte),
  );
  return {
    ...profile,
    peak_rss_bytes: peakRssBytes,
    peak_rss_mib: peakRssMiB,
    user_cpu_seconds: userSeconds,
    system_cpu_seconds: systemSeconds,
    elapsed_seconds: elapsedSeconds,
    planning_headroom: {
      measured_combined_process_memory_floor_mib: recommendedMemoryMiB,
      aggregate_spool_reserve_mib: aggregateSpoolReserveMiB,
      per_node_spool_reserve_mib: perNodeSpoolReserveMiB,
      max_node_spool_reserve_mib: Math.max(...perNodeSpoolReserveMiB),
      sustained_acceptance_per_second: profile.acceptance_per_second / 2,
      factor: 1.5,
      note: 'Synthetic single-process/single-host planning floors. Memory is combined across in-process nodes; disk reserves are separated by node. Validate on distinct target Debian hosts with representative MIME sizes, peer networking, and scanner concurrency.',
    },
  };
}

const results = counts.flatMap(messages => threadCounts.map(threads => timedRun(messages, threads)));
const violations = [];
for (const result of results) {
  const label = `${result.messages} messages at ${result.message_bytes} bytes across ${result.nodes} node(s)`;
  if (
    thresholds.min_accepts_per_second !== null
    && result.acceptance_per_second < thresholds.min_accepts_per_second
  ) violations.push(`${label}: ${result.acceptance_per_second}/s is below ${thresholds.min_accepts_per_second}/s`);
  if (
    thresholds.max_accept_p95_ms !== null
    && result.accept_p95_us / 1000 > thresholds.max_accept_p95_ms
  ) violations.push(`${label}: p95 ${result.accept_p95_us / 1000} ms exceeds ${thresholds.max_accept_p95_ms} ms`);
  if (
    thresholds.max_tail_p95_ms !== null
    && result.last_quarter_p95_us / 1000 > thresholds.max_tail_p95_ms
  ) violations.push(`${label}: tail p95 ${result.last_quarter_p95_us / 1000} ms exceeds ${thresholds.max_tail_p95_ms} ms`);
  if (
    thresholds.max_status_ms !== null
    && result.status_ms > thresholds.max_status_ms
  ) violations.push(`${label}: status ${result.status_ms} ms exceeds ${thresholds.max_status_ms} ms`);
}
const report = {
  passed: violations.length === 0,
  platform: `${os.platform()}-${os.arch()}`,
  release_profile: true,
  drain,
  nodes,
  node_weights: nodeWeights,
  replicas,
  thread_counts: threadCounts,
  thresholds,
  violations,
  results,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (violations.length > 0) process.exitCode = 1;
