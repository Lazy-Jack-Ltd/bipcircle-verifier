/**
 * File size ratchet (14 Nov 2026). Same shape as the transport layer ratchet
 * (BIPCircle-Transport-Layer test/fileSizeRatchet.test.ts at 1286959): one pure
 * evaluate() over measured files, ceilings in baselines JSON, controls on copies.
 *
 * Counts every tracked source file, tests included. Line count is
 * content.split('\n').length. Extensions are js, mjs, cjs, ts, tsx. Lock files,
 * generated output, vendored trees and node_modules are excluded.
 *
 * A file over 400 lines must be pinned at its exact size. A pinned file may not
 * grow. A pin higher than the file is now must fall. Counts and the total of the
 * pins may only fall, and they sit on the real measurement so a fall is banked.
 *
 * The thresholds and the file set are config. The per-file ceilings are the dated
 * baseline. The counts, the largest file and the total are constants below, so a
 * raise is a loud edit. No repo file is touched by the controls.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const CONFIG_PATH = join(HERE, 'baselines', 'file-size-config.json');
const BASELINE_PATH = join(HERE, 'baselines', 'file-size-2026-11-14.json');

const BASELINE_FILES_OVER_400 = 2;
const BASELINE_FILES_OVER_800 = 0;
const BASELINE_LOC_MAX = 711;
const MAX_TOTAL_PINNED_LOC = 1131;
const WARN_LOC_CEILING = 400;
const HARD_LOC_CEILING = 800;
const REQUIRED_ROOTS = ['src/', 'test/', 'bin/'];
const REQUIRED_EXCLUDED_DIRS = ['node_modules', 'dist', 'build', 'vendor', 'vendored', 'generated', 'coverage'];
const REQUIRED_EXTENSIONS = ['js', 'mjs', 'cjs', 'ts', 'tsx'];
const MIN_SOURCE_FILES = 22;
const MUST_INCLUDE = ['src/index.js', 'test/registryIdentity.test.js'];

function loadConfig() {
  const c = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  const ok =
    Number.isInteger(c.warnLoc) && Number.isInteger(c.hardLoc) && c.warnLoc > 0 && c.hardLoc > c.warnLoc &&
    Array.isArray(c.sourceRoots) && c.sourceRoots.length > 0 && c.sourceRoots.every((r) => typeof r === 'string' && r.endsWith('/')) &&
    Array.isArray(c.extensions) && c.extensions.length > 0 &&
    Array.isArray(c.excludedDirNames) && typeof c.excludedFilePattern === 'string';
  if (!ok) throw new Error('file-size-config.json is missing or malformed: the ratchet fails closed');
  return c;
}

const CONFIG = loadConfig();
const BASELINE = JSON.parse(readFileSync(BASELINE_PATH, 'utf8'));
const REAL_CONSTANTS = {
  filesOver400: BASELINE_FILES_OVER_400,
  filesOver800: BASELINE_FILES_OVER_800,
  locMax: BASELINE_LOC_MAX,
  totalPinned: MAX_TOTAL_PINNED_LOC,
};

function rootRegexes(cfg) {
  return cfg.sourceRoots.map(
    (p) => new RegExp('^' + p.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]+')),
  );
}

function isSource(file, cfg) {
  const ext = file.split('.').pop();
  const dirs = file.split('/').slice(0, -1);
  return (
    rootRegexes(cfg).some((r) => r.test(file)) &&
    cfg.extensions.includes(ext) &&
    !dirs.some((d) => cfg.excludedDirNames.includes(d)) &&
    !new RegExp(cfg.excludedFilePattern).test(file)
  );
}

function trackedFiles() {
  // GIT_INDEX_FILE is stripped: a path-scoped commit exports a partial index, and an inherited one
  // would make git ls-files see a handful of files. Failing to run git is a failure, never zero files.
  const env = { ...process.env };
  delete env.GIT_INDEX_FILE;
  const raw = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, maxBuffer: 1 << 28, env }).toString('utf8');
  return raw.split('\0').filter(Boolean);
}

function locOf(file) {
  return readFileSync(join(ROOT, file), 'utf8').split('\n').length;
}

function scan() {
  return trackedFiles()
    .filter((f) => isSource(f, CONFIG))
    .map((file) => ({ file, loc: locOf(file) }))
    .sort((a, b) => b.loc - a.loc || a.file.localeCompare(b.file));
}

/** Every ratchet rule, over a list of measured files. Pure, so the controls can feed it changed copies. */
function evaluate(rows, grand, k, warn, hard) {
  const out = [];
  const add = (rule, detail) => out.push({ rule, detail });
  const byPath = new Map(rows.map((r) => [r.file, r.loc]));

  for (const [file, entry] of Object.entries(grand)) {
    if (entry.grandfathered !== true) add('shape', `${file}: grandfathered must be true`);
    if (!Number.isInteger(entry.maxLoc) || entry.maxLoc <= warn) {
      add('shape', `${file}: maxLoc must be an integer over ${warn}`);
    }
    const reason = entry.reason;
    if (typeof reason !== 'string' || !reason.includes('GRANDFATHERED') || !reason.includes(String(entry.maxLoc))) {
      add('shape', `${file}: reason must say GRANDFATHERED and cite the pinned count ${entry.maxLoc}`);
    }
    const loc = byPath.get(file);
    if (loc === undefined) add('stale', `${file}: no longer a tracked source file, delete the entry and lower the total by ${entry.maxLoc}`);
    else if (loc <= warn) add('stale', `${file}: now ${loc} lines, ${warn} or fewer: delete the entry and lower the total by ${entry.maxLoc}`);
    else if (loc > entry.maxLoc) add('grown', `${file}: ${loc} lines, pinned ceiling ${entry.maxLoc} (+${loc - entry.maxLoc})`);
    else if (loc < entry.maxLoc) add('slack', `${file}: ${loc} lines, pinned at ${entry.maxLoc}: re-pin it down to ${loc} and lower the total`);
  }

  for (const r of rows) {
    if (r.loc > warn && !Object.prototype.hasOwnProperty.call(grand, r.file)) {
      add('unpinned', `${r.file}: ${r.loc} lines, over ${warn} with no grandfather entry`);
    }
  }

  const over400 = rows.filter((r) => r.loc > warn).length;
  const over800 = rows.filter((r) => r.loc > hard).length;
  const locMax = rows.reduce((m, r) => Math.max(m, r.loc), 0);
  const total = Object.values(grand).reduce((s, e) => s + e.maxLoc, 0);
  if (over400 > k.filesOver400) add('count400', `files over ${warn} rose to ${over400} (baseline ${k.filesOver400})`);
  if (over400 < k.filesOver400) add('count400', `files over ${warn} fell to ${over400}: lower BASELINE_FILES_OVER_400 from ${k.filesOver400} to bank it`);
  if (over800 > k.filesOver800) add('count800', `files over ${hard} rose to ${over800} (baseline ${k.filesOver800})`);
  if (over800 < k.filesOver800) add('count800', `files over ${hard} fell to ${over800}: lower BASELINE_FILES_OVER_800 from ${k.filesOver800} to bank it`);
  if (locMax > k.locMax) add('locMax', `largest file is ${locMax} lines, over the baseline ${k.locMax}`);
  if (locMax < k.locMax) add('locMax', `largest file fell to ${locMax}: lower BASELINE_LOC_MAX from ${k.locMax} to bank it`);
  if (total > k.totalPinned) add('total', `total pinned ceiling is ${total}, over ${k.totalPinned} (+${total - k.totalPinned}): a ceiling was raised`);
  if (total < k.totalPinned) add('total', `total pinned ceiling fell to ${total}: lower MAX_TOTAL_PINNED_LOC from ${k.totalPinned} to bank it`);
  return out;
}

const rules = (p) => [...new Set(p.map((x) => x.rule))].sort();
const show = (p) => p.map((x) => `  [${x.rule}] ${x.detail}`).join('\n');
const REMEDY = 'Split the file. A ceiling is never raised; a fall is banked by re-pinning down in the baseline and lowering the constants in this test.';
const has = (found, ...wanted) => {
  for (const w of wanted) assert.ok(found.includes(w), `expected rule ${w} to fire, got ${found.join(', ') || 'nothing'}`);
};

const REAL_ROWS = scan();
const REAL_PROBLEMS = evaluate(REAL_ROWS, BASELINE.grandfathered, REAL_CONSTANTS, CONFIG.warnLoc, CONFIG.hardLoc);
const PLANT = `${CONFIG.sourceRoots[0]}brandNewFile.${CONFIG.extensions[0]}`;

describe('file size ratchet', () => {
  it('the config cannot loosen the ratchet and the scanner is not vacuous', () => {
    assert.ok(CONFIG.warnLoc <= WARN_LOC_CEILING, 'warnLoc raised past 400');
    assert.ok(CONFIG.hardLoc <= HARD_LOC_CEILING, 'hardLoc raised past 800');
    for (const root of REQUIRED_ROOTS) assert.ok(CONFIG.sourceRoots.includes(root), `root ${root} dropped from the config`);
    for (const dir of REQUIRED_EXCLUDED_DIRS) assert.ok(CONFIG.excludedDirNames.includes(dir), `${dir} no longer excluded`);
    for (const ext of REQUIRED_EXTENSIONS) assert.ok(CONFIG.extensions.includes(ext), `${ext} dropped from the extensions`);
    assert.ok(REAL_ROWS.length >= MIN_SOURCE_FILES, `the scanner found only ${REAL_ROWS.length} files, it is matching almost nothing`);
  });

  it('the scanner counts tracked source files, including tests, and skips lock, generated, vendored and node_modules', () => {
    const tracked = new Set(trackedFiles());
    for (const { file } of REAL_ROWS) {
      assert.ok(tracked.has(file), `${file} is counted but not tracked`);
      assert.ok(!/node_modules|\/dist\/|\/build\/|\/vendor\/|\/vendored\/|\/generated\//.test(file), `excluded tree in the source set: ${file}`);
      assert.ok(!/\.(generated|min)\./.test(file), `generated file in the source set: ${file}`);
    }
    for (const file of MUST_INCLUDE) assert.ok(REAL_ROWS.some((r) => r.file === file), `${file} was dropped from the scan`);
    const independent = [...tracked].filter((f) => isSource(f, CONFIG)).sort();
    assert.deepEqual(REAL_ROWS.map((r) => r.file).sort(), independent);
  });

  it('no grandfathered file has grown past its pinned ceiling', () => {
    const grown = REAL_PROBLEMS.filter((p) => p.rule === 'grown');
    assert.equal(grown.length, 0, `${show(grown)}\n${REMEDY}`);
  });

  it('every file over 400 lines is individually grandfathered', () => {
    const unpinned = REAL_PROBLEMS.filter((p) => p.rule === 'unpinned');
    assert.equal(unpinned.length, 0, `${show(unpinned)}\n${REMEDY}`);
  });

  it('no ceiling sits above its file, and no stale entry remains (re-pin down, delete once 400 or fewer)', () => {
    const bad = REAL_PROBLEMS.filter((p) => p.rule === 'slack' || p.rule === 'stale');
    assert.equal(bad.length, 0, show(bad));
  });

  it('counts may only fall: files over 400, files over 800, the largest file', () => {
    const bad = REAL_PROBLEMS.filter((p) => ['count400', 'count800', 'locMax'].includes(p.rule));
    assert.equal(bad.length, 0, `${show(bad)}\n${REMEDY}`);
  });

  it('the total of every pinned ceiling may only fall, and sits on the real sum', () => {
    const bad = REAL_PROBLEMS.filter((p) => p.rule === 'total');
    assert.equal(bad.length, 0, `${show(bad)}\n${REMEDY}`);
  });

  it('every grandfather entry is shaped and justified', () => {
    const bad = REAL_PROBLEMS.filter((p) => p.rule === 'shape');
    assert.equal(bad.length, 0, show(bad));
  });

  it('nothing else is wrong', () => {
    assert.equal(REAL_PROBLEMS.length, 0, show(REAL_PROBLEMS));
  });
});

describe('file size ratchet controls: each of these changes must be refused', () => {
  const grand = () => structuredClone(BASELINE.grandfathered);
  const rows = () => structuredClone(REAL_ROWS);
  const run = (r, g, k = REAL_CONSTANTS) => evaluate(r, g, k, CONFIG.warnLoc, CONFIG.hardLoc);

  function pinnedVictim(r, g) {
    const list = r.filter((x) => x.loc > CONFIG.warnLoc && Object.prototype.hasOwnProperty.call(g, x.file));
    const found = list[list.length - 1];
    if (found) return found;
    const made = { file: PLANT, loc: CONFIG.warnLoc + 1 };
    r.push(made);
    g[PLANT] = { grandfathered: true, maxLoc: made.loc, reason: `GRANDFATHERED at ${made.loc} lines` };
    return made;
  }

  it('control: the unchanged tree passes (the controls start from a clean state)', () => {
    assert.deepEqual(run(rows(), grand()), []);
  });

  it('control: a grandfathered file grown by one line past its ceiling fails', () => {
    const r = rows();
    const g = grand();
    const victim = pinnedVictim(r, g);
    victim.loc += 1;
    const problems = run(r, g);
    has(rules(problems), 'grown');
    assert.ok(problems.some((p) => p.rule === 'grown' && p.detail.startsWith(victim.file) && p.detail.includes('(+1)')));
  });

  it('control: a new file of 401 lines that is not pinned fails', () => {
    const r = [...rows(), { file: PLANT, loc: 401 }];
    has(rules(run(r, grand())), 'unpinned');
  });

  it('control: a pin raised by one fails', () => {
    const r = rows();
    const g = grand();
    const keys = Object.keys(g);
    const file = keys[0];
    if (file) {
      g[file].maxLoc += 1;
      g[file].reason = `GRANDFATHERED at ${g[file].maxLoc} lines`;
      has(rules(run(r, g)), 'slack');
      return;
    }
    r.push({ file: PLANT, loc: 500 });
    g[PLANT] = { grandfathered: true, maxLoc: 501, reason: 'GRANDFATHERED at 501 lines' };
    has(rules(run(r, g)), 'slack');
  });

  it('control: a file that shrank but kept its old ceiling fails until it is re-pinned down', () => {
    const r = rows();
    const g = grand();
    const victim = pinnedVictim(r, g);
    const before = victim.loc;
    victim.loc -= 1;
    if (victim.loc <= CONFIG.warnLoc) g[victim.file].maxLoc = before;
    has(rules(run(r, g)), victim.loc <= CONFIG.warnLoc ? 'stale' : 'slack');
  });

  it('control: a file that fell to 400 lines or fewer and kept its entry fails', () => {
    const r = rows();
    const g = grand();
    const victim = pinnedVictim(r, g);
    victim.loc = CONFIG.warnLoc;
    has(rules(run(r, g)), 'stale');
  });

  it('control: the total constant raised above the real sum fails (a quiet raise has no headroom)', () => {
    const k = { ...REAL_CONSTANTS, totalPinned: REAL_CONSTANTS.totalPinned + 1 };
    has(rules(run(rows(), grand(), k)), 'total');
  });

  it('control: the scanner keeps tests in, and lock, generated, vendored and node_modules out', () => {
    const root = CONFIG.sourceRoots[0];
    const ext = CONFIG.extensions[0];
    assert.equal(isSource(`${root}a.${ext}`, CONFIG), true);
    assert.equal(isSource(`${root}a.test.${ext}`, CONFIG), true);
    assert.equal(isSource(`${root}node_modules/a.${ext}`, CONFIG), false);
    assert.equal(isSource(`${root}dist/a.${ext}`, CONFIG), false);
    assert.equal(isSource(`${root}vendor/a.${ext}`, CONFIG), false);
    assert.equal(isSource(`${root}generated/a.${ext}`, CONFIG), false);
    assert.equal(isSource(`${root}a.generated.${ext}`, CONFIG), false);
    assert.equal(isSource(`${root}package-lock.json`, CONFIG), false);
    assert.equal(isSource(`outside/a.${ext}`, CONFIG), false);
  });
});
