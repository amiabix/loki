// Build the per-engine table from the summary JSON each drill run writes.
//
// Every cell comes from a recorded run. An engine that did not launch is printed as
// NOT RUN with its exact error, never as a blank or a pass.

import { readdir, readFile } from 'node:fs/promises';

const dir = process.argv[2] || '/tmp/loki-g3';
const files = (await readdir(dir)).filter((f) => /^summary-.*\.json$/.test(f)).sort();
if (!files.length) { console.error(`no summaries in ${dir}`); process.exit(1); }

const runs = [];
for (const f of files) runs.push(JSON.parse(await readFile(`${dir}/${f}`, 'utf8')));

// The five categories the request named, mapped to the drills that cover them.
const CATEGORIES = [
  ['receipt gate', ['gate-three-honest', 'gate-only-one-reachable']],
  ['two-tab race', ['two-tabs-no-lock', 'two-tabs-same-package-no-lock']],
  ['crash recovery', ['hard-kill-after-consume']],
  ['profile restore', ['restore-three-honest', 'restore-all-acknowledgers-lying']],
  ['strict durability', ['durability-unsupported-is-not-a-pass']],
];

function cell(run, names) {
  if (run.status) return 'NOT RUN';
  const got = names.map((n) => run.drills.find((d) => d.name === n)).filter(Boolean);
  if (!got.length) return 'not in suite';
  if (got.some((d) => d.unsupported)) return 'UNSUPPORTED';
  // A drill can satisfy its own assertion and still not be evidence about the platform.
  // `inconclusive` wins over `ok` so such a drill is never counted as a pass.
  const inc = got.filter((d) => d.inconclusive).length;
  const exp = got.filter((d) => !d.inconclusive && d.expected_failure).length;
  const pass = got.filter((d) => d.ok && !d.inconclusive && !d.expected_failure).length;
  const parts = [];
  if (pass) parts.push(`${pass} pass`);
  if (exp) parts.push(`${exp} expected fail`);
  if (inc) parts.push(`${inc} inconclusive`);
  return parts.join(', ');
}

const w = (s, n) => String(s).padEnd(n);
const COL = 26;
const LBL = 22;

console.log();
console.log(`${w('engine', 12)}${w('version', 18)}${w('playwright-core', 17)}suite`);
console.log('-'.repeat(70));
for (const r of runs) {
  console.log(`${w(r.engine, 12)}${w(r.engine_version, 18)}${w(r.playwright_core, 17)}${r.suite}`);
}

console.log();
console.log(`${w('category', LBL)}${runs.map((r) => w(r.engine, COL)).join('')}`);
console.log('-'.repeat(LBL + COL * runs.length));
for (const [label, names] of CATEGORIES) {
  console.log(`${w(label, LBL)}${runs.map((r) => w(cell(r, names), COL)).join('')}`);
}

console.log();
console.log(`${w('renderer-crash URL', LBL)}${runs.map((r) => w(r.renderer_crash_url ?? 'none', COL)).join('')}`);
console.log(`${w('durability support', LBL)}${runs.map((r) =>
  w(r.real_durability ? String(r.real_durability.supported) : 'not measured', COL)).join('')}`);
console.log(`${w('durability reflected', LBL)}${runs.map((r) =>
  w(r.real_durability ? String(r.real_durability.reflected) : 'not measured', COL)).join('')}`);

for (const r of runs) {
  if (!r.status) continue;
  console.log();
  console.log(`${r.engine}: ${r.status}`);
  console.log(`  playwright call: ${r.launch_error}`);
  for (const line of r.engine_stderr ?? []) console.log(`  engine stderr:   ${line}`);
}

console.log();
console.log('Playwright WebKit is a Playwright-shipped WebKit build. It is NOT Safari.');
console.log('Native Safari: NOT TESTED. safaridriver exposes no profile-isolation flag.');
