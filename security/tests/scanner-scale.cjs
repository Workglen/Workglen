'use strict';

// Release-mode resource wrapper for the ignored scanner concurrency profile.
// Usage: node security/tests/scanner-scale.cjs [messages] [thread-counts] [message-bytes]
// Example: node security/tests/scanner-scale.cjs 500 1,2,4,8 65536

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const os = require('node:os');

const messages = Number(process.argv[2] || 500);
const threadCounts = (process.argv[3] || '1,2,4,8').split(',').map(Number);
const messageBytes = Number(process.argv[4] || 65536);
assert(Number.isInteger(messages) && messages >= 100 && messages <= 10000);
assert(threadCounts.length > 0 && threadCounts.every(value => Number.isInteger(value) && value >= 1 && value <= 16));
assert(Number.isInteger(messageBytes) && messageBytes >= 256 && messageBytes <= 10 * 1024 * 1024);
assert(messages * messageBytes <= 1024 ** 3, 'Scale point exceeds the one-GiB content ceiling');

const build = childProcess.spawnSync(
  'cargo',
  ['test', '--release', '--no-run', '--message-format=json', 'scanner_concurrency_scaling_profile'],
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

function timedRun(threads) {
  const platform = os.platform();
  const timeArguments = platform === 'darwin' ? ['-l'] : ['-v'];
  timeArguments.push(
    executable,
    'scanner_concurrency_scaling_profile',
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
      WORKGLEN_SCANNER_SCALE_MESSAGES: String(messages),
      WORKGLEN_SCANNER_SCALE_THREADS: String(threads),
      WORKGLEN_SCANNER_SCALE_MESSAGE_BYTES: String(messageBytes),
    },
  });
  if (result.status !== 0) throw Error(result.error || result.stderr || result.stdout);
  const marker = result.stdout.match(/SCANNER_SCALE (\{[^\n]+\})/);
  assert(marker, result.stdout);
  const profile = JSON.parse(marker[1]);
  let peakRssBytes;
  let userSeconds;
  let systemSeconds;
  if (platform === 'darwin') {
    peakRssBytes = numberFrom(result.stderr, /^\s*(\d+)\s+maximum resident set size$/m);
    const times = result.stderr.match(/^\s*([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys$/m);
    if (times) {
      userSeconds = Number(times[2]);
      systemSeconds = Number(times[3]);
    }
  } else {
    const peakRssKiB = numberFrom(result.stderr, /Maximum resident set size \(kbytes\):\s*(\d+)/);
    peakRssBytes = peakRssKiB === null ? null : peakRssKiB * 1024;
    userSeconds = numberFrom(result.stderr, /User time \(seconds\):\s*([\d.]+)/);
    systemSeconds = numberFrom(result.stderr, /System time \(seconds\):\s*([\d.]+)/);
  }
  return {
    ...profile,
    peak_rss_bytes: peakRssBytes,
    peak_rss_mib: peakRssBytes === null ? null : peakRssBytes / 1024 ** 2,
    user_cpu_seconds: userSeconds,
    system_cpu_seconds: systemSeconds,
  };
}

const results = threadCounts.map(timedRun);
const report = {
  passed: results.every(result => result.peak_active <= result.threads),
  platform: `${os.platform()}-${os.arch()}`,
  release_profile: true,
  messages,
  message_bytes: messageBytes,
  thread_counts: threadCounts,
  scope: 'Synthetic local inspection and encrypted queue finalization; sender-authentication DNS and downstream SMTP are excluded.',
  results,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (!report.passed) process.exitCode = 1;
