// Daily health check: can the published checker still do its job?
// Runs a real check of the sample site against the live lookup services and
// fails (so GitHub sends a failure email) if any part has stopped working.
import { readFileSync } from 'node:fs';
import { parseSiteHealth, checkSite, classify } from '../site/lib.js';

const PAGE = process.env.SITE_URL || 'https://baronyofglyndwfn.github.io/site-check/';
const problems = [];
const fail = (msg) => { problems.push(msg); console.error('FAIL ' + msg); };
const ok = (msg) => console.log('ok   ' + msg);

const fetchJson = async (url) => {
  const r = await fetch(url, { headers: { Accept: 'application/json', 'User-Agent': 'webminister-site-check-health' } });
  if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`);
  return r.json();
};

// 1. The page and its bulletins are being served.
try {
  const r = await fetch(PAGE);
  const html = await r.text();
  if (r.ok && html.includes('Webminister Site Check')) ok(`page ${PAGE}`);
  else fail(`page ${PAGE} returned ${r.status}`);
  const b = await fetchJson(new URL('bulletins.json', PAGE).href);
  if (Array.isArray(b) && b.length) ok(`bulletins.json (${b.length})`);
  else fail('bulletins.json is empty or not a list');
} catch (e) {
  fail(`page: ${e.message}`);
}

// 2. A full check of the sample site still finds what it should.
try {
  const sample = readFileSync(new URL('../test/fixtures/site-health-sample.txt', import.meta.url), 'utf8');
  const results = await checkSite(parseSiteHealth(sample), fetchJson);
  const groups = Object.fromEntries(classify(results).map((e) => [e.item.name, e.group]));
  results.core.checked && results.core.vulns.length ? ok('WordPress 7.1.3 lookup finds known problems') : fail('WordPress core lookup returned nothing for 7.1.3');
  results.php?.checked ? ok('PHP lookup') : fail('PHP lookup failed');
  groups['The Events Calendar'] === 'fix' ? ok('The Events Calendar 6.18.2 → Fix now') : fail(`The Events Calendar 6.18.2 landed in "${groups['The Events Calendar']}", expected "fix"`);
  const akismet = results.items.find((i) => i.name.startsWith('Akismet'));
  akismet?.slug === 'akismet' ? ok('wordpress.org name matching') : fail('wordpress.org name matching failed for Akismet');
} catch (e) {
  fail(`site check: ${e.message}`);
}

// 3. The official CVE list is still being published where the watcher reads it.
try {
  const r = await fetch('https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json');
  const log = await r.json();
  const newest = log.reduce((m, e) => (e.fetchTime > m ? e.fetchTime : m), '');
  const hours = (Date.now() - Date.parse(newest)) / 3600e3;
  hours < 12 ? ok(`CVE list updated ${hours.toFixed(1)} h ago`) : fail(`CVE list last updated ${hours.toFixed(1)} h ago`);
} catch (e) {
  fail(`CVE list: ${e.message}`);
}

if (problems.length) {
  console.error(`\n${problems.length} problem(s). The checker or the watcher may be giving wrong or no answers.`);
  process.exit(1);
}
console.log('\nAll good.');
