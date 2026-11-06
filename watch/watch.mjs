// Bulletin watcher. Finds new vulnerabilities for the products in
// watch/watchlist.json and appends plain-language drafts to site/bulletins.json.
//
//   node watch/watch.mjs --state <seen.json> [--baseline] [--since <ISO time>] [--dry-run]
//
// Sources:
//   1. The official CVE list (CVEProject/cvelistV5 deltaLog: every new CVE in the last 30 days)
//   2. WPVulnerability (adds Wordfence/Patchstack/WPScan entries, sometimes weeks before a CVE)
//   3. WordPress core's GitHub security advisories (core releases often have no CVE)
//
// State (which ids have been seen, how far into the CVE log we've read) lives in
// --state; the workflow keeps it on the unpublished `watch-state` branch.
// --baseline marks everything currently known as seen without drafting anything.
// Exit code 0 always unless something is broken; writes `drafted=<n>` and
// `urgent=<true|false>` to $GITHUB_OUTPUT and a PR body to watch/.pr-body.md.

import { readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { matchCve, fromWpv, groupFindings, draftBulletin, isUrgent, phpBranchWatched, coveredIdSet, fingerprintOf, patchedVersions } from './lib.mjs';

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const flag = (name) => args.includes(name);

const ROOT = new URL('..', import.meta.url);
const statePath = opt('--state') || new URL('watch/seen.json', ROOT).pathname;
const watch = JSON.parse(readFileSync(new URL('watch/watchlist.json', ROOT), 'utf8'));
const bulletinsPath = new URL('site/bulletins.json', ROOT);
const state = existsSync(statePath)
  ? JSON.parse(readFileSync(statePath, 'utf8'))
  : { ids: [], fingerprints: [], cveSince: null };
const seen = new Set(state.ids);
// Products already being watched. A newly added product's existing history is
// recorded as seen without drafting, so only problems found after it was added
// become bulletins (the checker covers the old ones).
const knownProducts = new Set(state.products || []);
const productKey = (kind, slug) => `${kind}/${slug}`;
const silent = new Set();
const fingerprints = new Set(state.fingerprints || []);
const today = new Date().toISOString().slice(0, 10);

const problems = []; // non-fatal source failures, reported at the end

const UA = { 'User-Agent': 'webminister-site-check-watcher (+https://github.com/BaronyOfGlynDwfn/site-check)' };

async function getJson(url, headers = {}) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = await fetch(url, { headers: { ...UA, Accept: 'application/json', ...headers } });
    if (r.status === 404) return null;
    if (r.ok) return r.json();
    if (r.status === 429 || r.status >= 500) {
      await new Promise((res) => setTimeout(res, 2000 * (attempt + 1)));
      continue;
    }
    throw new Error(`HTTP ${r.status} for ${url}`);
  }
  throw new Error(`gave up on ${url}`);
}

async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  }));
  return out;
}

// --- 1. Official CVE list ----------------------------------------------------
async function fromCveList() {
  let log;
  try {
    log = await getJson('https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json');
    if (!Array.isArray(log)) throw new Error('unexpected format');
  } catch (e) {
    problems.push(`CVE list: ${e.message}`);
    return { found: [], latest: state.cveSince }; // read from the same point next time
  }
  const since = opt('--since') || state.cveSince || new Date(Date.now() - 36 * 3600e3).toISOString();
  const fresh = log.filter((e) => e.fetchTime > since);
  let latest = log.reduce((m, e) => (e.fetchTime > m ? e.fetchTime : m), since);
  const links = new Map();
  const loggedAt = new Map();
  for (const e of fresh) for (const n of e.new || []) {
    links.set(n.cveId, n.githubLink);
    if (!loggedAt.has(n.cveId) || e.fetchTime < loggedAt.get(n.cveId)) loggedAt.set(n.cveId, e.fetchTime);
  }
  const ids = [...links.keys()];
  console.log(`CVE list: ${ids.length} new CVEs since ${since}`);
  const failed = [];
  const records = await pool(ids, 8, (id) => getJson(links.get(id)).catch((err) => {
    console.warn(`  could not fetch ${id}: ${err.message}`);
    failed.push(id);
    return null;
  }));
  if (failed.length) {
    // Read the log again from just before the first failure next time, so a
    // record that failed to download is retried rather than lost.
    const first = failed.map((id) => loggedAt.get(id)).sort()[0];
    latest = new Date(Date.parse(first) - 1).toISOString();
    problems.push(`${failed.length} CVE record(s) failed to download; will retry from ${latest}`);
  }
  const found = records.map((r) => (r ? matchCve(r, watch) : null)).filter(Boolean)
    .filter((f) => phpBranchWatched(f, watch.php || []));
  return { found, latest };
}

// --- 2. WPVulnerability ------------------------------------------------------
async function fromWpvList() {
  const found = [];
  const targets = [
    ...watch.plugins.map((p) => ({ kind: 'plugin', ...p })),
    ...watch.themes.map((t) => ({ kind: 'theme', ...t })),
  ];
  await pool(targets, 5, async (t) => {
    let data;
    try {
      data = (await getJson(`https://www.wpvulnerability.net/${t.kind}/${encodeURIComponent(t.slug)}/`))?.data;
    } catch (e) {
      problems.push(`WPVulnerability ${t.kind} ${t.slug}: ${e.message}`);
      return; // not added to knownProducts, so a later success isn't treated as a new product
    }
    const isNewProduct = state.products && !knownProducts.has(productKey(t.kind, t.slug));
    for (const rec of data?.vulnerability || []) {
      const f = fromWpv(rec, t.kind, t.slug, t.name);
      if (isNewProduct) silent.add(f.id);
      found.push(f);
    }
    knownProducts.add(productKey(t.kind, t.slug));
  });
  for (const b of watch.php || []) {
    let data;
    try {
      data = (await getJson(`https://www.wpvulnerability.net/php/${b}.0/`))?.data;
    } catch (e) {
      problems.push(`WPVulnerability PHP ${b}: ${e.message}`);
      continue;
    }
    for (const rec of data?.vulnerability || []) {
      const f = fromWpv(rec, 'php', null, 'PHP');
      if (f.fixedIn.every((v) => v.startsWith(b + '.'))) found.push(f);
    }
  }
  console.log(`WPVulnerability: ${found.length} records across ${targets.length} products and ${(watch.php || []).length} PHP branches`);
  return found;
}

// --- 3. WordPress core advisories --------------------------------------------
async function fromCoreAdvisories() {
  if (!watch.core) return [];
  const headers = process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {};
  let list;
  try {
    list = await getJson('https://api.github.com/repos/WordPress/wordpress-develop/security-advisories?per_page=50&sort=published&direction=desc', headers);
  } catch (e) {
    problems.push(`WordPress core advisories: ${e.message}`);
    return [];
  }
  return (list || []).map((a) => ({
    source: 'github-advisory',
    id: a.ghsa_id,
    cves: a.cve_id ? [a.cve_id] : [],
    kind: 'core',
    slug: null,
    name: 'WordPress',
    title: a.summary,
    description: a.description || '',
    cwes: (a.cwes || []).map((c) => c.cwe_id),
    privileges: null,
    severity: a.severity && a.severity !== 'unknown' ? a.severity : null,
    exploited: false,
    // patched_versions is range text such as ">= 7.1.4" or "6.9.11, 7.0.8": keep the version numbers.
    fixedIn: [...new Set((a.vulnerabilities || []).flatMap((v) => patchedVersions(v.patched_versions)))],
    through: null,
    unfixed: false,
    published: (a.published_at || '').slice(0, 10),
    links: [a.html_url].filter(Boolean),
  }));
}

const fingerprint = fingerprintOf;

// --sources cve,wpv,core (default all) — mainly for testing one source at a time.
const sources = (opt('--sources') || 'cve,wpv,core').split(',');
const [cve, wpv, core] = await Promise.all([
  sources.includes('cve') ? fromCveList() : { found: [], latest: state.cveSince },
  sources.includes('wpv') ? fromWpvList() : [],
  sources.includes('core') ? fromCoreAdvisories() : [],
]);
const all = [...cve.found, ...wpv, ...core];
const isNew = (f) => !seen.has(f.id) && !f.cves.some((c) => seen.has(c)) && !(fingerprint(f) && fingerprints.has(fingerprint(f)));
const fresh = all.filter((f) => isNew(f) && !silent.has(f.id));

const remember = () => {
  for (const f of all) {
    seen.add(f.id);
    f.cves.forEach((c) => seen.add(c));
  }
  for (const f of fresh) if (fingerprint(f)) fingerprints.add(fingerprint(f));
  const next = {
    ids: [...seen].sort(),
    fingerprints: [...fingerprints].sort(),
    products: [...knownProducts].sort(),
    cveSince: cve.latest,
    updated: new Date().toISOString(),
  };
  if (!flag('--dry-run')) writeFileSync(statePath, JSON.stringify(next, null, 1) + '\n');
};

const out = (k, v) => process.env.GITHUB_OUTPUT && appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${v}\n`);

if (flag('--baseline')) {
  remember();
  console.log(`Baseline: marked ${seen.size} ids as seen; CVE list read up to ${cve.latest}.`);
  out('drafted', 0);
  out('urgent', false);
  process.exit(0);
}

const bulletins = JSON.parse(readFileSync(bulletinsPath, 'utf8'));
// Drafts already waiting in the open PR (--pending <its bulletins.json>): kept,
// with any wording edits, and re-applied on top of the current main.
const pendingPath = opt('--pending');
const onMain = new Set(bulletins.map((b) => b.id));
const pending = pendingPath && existsSync(pendingPath)
  ? JSON.parse(readFileSync(pendingPath, 'utf8')).filter((b) => !onMain.has(b.id))
  : [];
// Anything an existing or pending bulletin already names is covered.
const coveredIds = coveredIdSet([...pending, ...bulletins]);
const isCovered = (f) => f.cves.some((c) => coveredIds.has(c)) || coveredIds.has(f.id);
const groups = groupFindings(fresh.filter((f) => !isCovered(f)), watch);

// The product's current release, so a draft can say "update to 6.18.3.1".
async function currentVersion(g) {
  try {
    if (g.kind === 'core') return (await getJson('https://api.wordpress.org/core/version-check/1.7/'))?.offers?.[0]?.current || null;
    if (g.kind === 'plugin' || g.kind === 'theme') {
      const api = g.kind === 'plugin' ? 'plugins/info/1.2/?action=plugin_information' : 'themes/info/1.2/?action=theme_information';
      return (await getJson(`https://api.wordpress.org/${api}&request[slug]=${encodeURIComponent(g.slug)}&request[fields][sections]=0&request[fields][description]=0`))?.version || null;
    }
  } catch (e) {
    console.warn(`  no current version for ${g.name}: ${e.message}`);
  }
  return null;
}
await pool(groups, 5, async (g) => { g.current = await currentVersion(g); });
const ids = new Set([...pending, ...bulletins].map((b) => b.id));
const drafts = [];
for (const g of groups) {
  const d = draftBulletin(g, today);
  let id = d.id;
  for (let i = 2; ids.has(id); i++) id = `${d.id}-${i}`;
  d.id = id;
  ids.add(id);
  drafts.push({ draft: d, group: g });
}

const urgent = groups.some((g) => isUrgent(g.vulns));
console.log(`New findings: ${fresh.length}; drafted ${drafts.length} bulletin(s); urgent=${urgent}`);
for (const { draft } of drafts) console.log(`  [${draft.severity}] ${draft.title}`);

if (!flag('--dry-run')) {
  if (drafts.length || pending.length) {
    writeFileSync(bulletinsPath, JSON.stringify([...drafts.map((d) => d.draft), ...pending, ...bulletins], null, 2) + '\n');
  }
  if (drafts.length) {
    const body = [
      urgent ? '**URGENT: at least one of these can be used without logging in, is rated critical, or is already being attacked.**\n' : '',
      'The watcher found new security problems for products on the watchlist and drafted these bulletins. They were written from templates, so check the wording before merging. Merging publishes them.',
      '',
      ...drafts.map(({ draft, group }) => [
        `### ${draft.title} (${draft.severity})`,
        draft.summary,
        '',
        ...group.vulns.map((v) => `- ${v.cves.join(', ') || v.id}: ${v.title} [${v.source}${v.published ? ', ' + v.published : ''}]`),
        '',
      ].join('\n')),
      'To change the wording, edit `site/bulletins.json` on this branch. To drop a draft, delete its entry. The watcher remembers what it has seen, so closing this PR does not bring the same items back.',
    ].join('\n');
    writeFileSync(new URL('watch/.pr-body.md', ROOT), body);
  }
  remember();
}
out('drafted', drafts.length);
out('urgent', urgent);
out('pending', pending.length);
if (problems.length) {
  console.warn(`\n${problems.length} source problem(s) this run (other sources were still checked):`);
  for (const p of problems) console.warn('  - ' + p);
  out('problems', problems.length);
}
