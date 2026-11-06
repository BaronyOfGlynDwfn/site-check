import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseSiteHealth, parseItemLine, compareVersions, affects, fixedIn,
  matchVulns, contradictedBySources, checkSite, classify, hostEmail, findSlug, normName, bulletinApplies,
} from '../site/lib.js';

const sample = readFileSync(new URL('./fixtures/site-health-sample.txt', import.meta.url), 'utf8');

test('parses core, PHP, database and every plugin/theme line', () => {
  const info = parseSiteHealth(sample);
  assert.equal(info.wordpress, '7.1.3');
  assert.equal(info.php, '8.3.35');
  assert.equal(info.userRegistration, true);
  const names = info.items.map((i) => `${i.kind}/${i.status}/${i.name}`);
  assert.deepEqual(names, [
    'plugin/active/Akismet Anti-spam: Spam Protection',
    'plugin/active/All-In-One Security (AIOS) – Security and Firewall',
    'plugin/active/The Events Calendar',
    'plugin/active/Example Custom Plugin',
    'plugin/active/Abandoned Gallery',
    'plugin/inactive/Hello Dolly',
    'plugin/inactive/Old Snapshot',
    'mu-plugin/active/p3-profiler.php',
    'theme/active/Herald Mobile',
    'theme/parent/Herald',
    'theme/inactive/Neve',
    'theme/inactive/Twenty Twenty-Five',
  ]);
  const tec = info.items.find((i) => i.name === 'The Events Calendar');
  assert.equal(tec.version, '6.18.2');
  assert.equal(tec.latest, '6.18.3.1');
  assert.equal(info.items.find((i) => i.name === 'Herald Mobile').slug, 'herald-mobile');
  assert.equal(info.items.find((i) => i.name === 'Old Snapshot').version, '1.0.0');
  assert.equal(info.items.find((i) => i.kind === 'mu-plugin').version, null);
});

test('rejects text that is not Site Health info', () => {
  assert.throws(() => parseSiteHealth('hello'), /Site Health/);
});

test('plugin line with commas in author', () => {
  const p = parseItemLine('UpdraftPlus - Backup/Restore: version: 1.26.14, author: TeamUpdraft, DavidAnderson, Auto-updates disabled');
  assert.equal(p.name, 'UpdraftPlus - Backup/Restore');
  assert.equal(p.version, '1.26.14');
  assert.equal(p.latest, null);
  assert.equal(p.autoUpdates, false);
});

test('version comparison', () => {
  assert.equal(compareVersions('6.18.2', '6.18.3'), -1);
  assert.equal(compareVersions('6.18.3.1', '6.18.3'), 1);
  assert.equal(compareVersions('7.1', '7.1.0'), 0);
  assert.equal(compareVersions('1.0.0', '1.0.0'), 0);
  assert.equal(compareVersions('2.0-beta1', '2.0'), -1);
  assert.equal(compareVersions('2.0-RC1', '2.0-beta2'), 1);
  assert.equal(compareVersions('10.0', '9.9.9'), 1);
});

test('operator ranges', () => {
  const lt = { max_operator: 'lt', max_version: '6.18.3', unfixed: 0 };
  assert.ok(affects('6.18.2', lt));
  assert.ok(!affects('6.18.3', lt));
  assert.ok(!affects('6.18.3.1', lt));
  assert.equal(fixedIn(lt), '6.18.3');
  const le = { max_operator: 'le', max_version: '2.0', unfixed: 0 };
  assert.ok(affects('2.0', le));
  assert.equal(fixedIn(le), null);
  const ranged = { min_operator: 'ge', min_version: '6.6', max_operator: 'lt', max_version: '7.1.4', unfixed: 0 };
  assert.ok(!affects('6.5.9', ranged));
  assert.ok(affects('7.1.3', ranged));
  const unfixed = { unfixed: '1' };
  assert.ok(affects('9.9', unfixed));
  assert.ok(!affects('1.0', undefined), 'no operator: skip unless the endpoint is per-version');
  assert.ok(affects('1.0', undefined, true));
});

// --- end-to-end with a fake network -------------------------------------
const vuln = (max, extra = {}) => ({
  name: `x < ${max}`,
  operator: { max_operator: 'lt', max_version: max, unfixed: 0 },
  source: [{ id: 'CVE-2026-1', name: 'CVE-2026-1' }, { id: 'abc', name: 'Stored XSS', link: 'https://example.org/v' }],
  impact: { cvss: { severity: 'm' }, ssvc: { kev: false } },
  ...extra,
});

const pluginIndex = {
  'Akismet Anti-spam: Spam Protection': 'akismet',
  'All-In-One Security (AIOS) &#8211; Security and Firewall': 'all-in-one-wp-security-and-firewall',
  'The Events Calendar': 'the-events-calendar',
  'Abandoned Gallery': 'abandoned-gallery',
  'Hello Dolly': 'hello-dolly',
};
const vulnDb = {
  'plugin/akismet': { name: 'Akismet', vulnerability: [] },
  'plugin/all-in-one-wp-security-and-firewall': { name: 'AIOS', vulnerability: [vuln('5.0')] },
  'plugin/the-events-calendar': { name: 'TEC', vulnerability: [vuln('6.18.3'), vuln('6.18.2')] },
  'plugin/abandoned-gallery': { name: 'AG', closed: 1, closed_reason: 'unknown', vulnerability: [] },
  'plugin/hello-dolly': { name: 'HD', vulnerability: [] },
  'theme/herald-mobile': { vulnerability: null },
  'theme/herald': { name: 'Herald Pro Magazine', vulnerability: [vuln('9.0')] },
  'theme/neve': { name: 'Neve', vulnerability: [] },
  'theme/twentytwentyfive': { name: 'TT5', vulnerability: [] },
};

async function fakeFetch(url) {
  const u = new URL(url);
  if (u.hostname === 'api.wordpress.org') {
    if (u.pathname.startsWith('/core/version-check')) return { offers: [{ current: '7.1.4' }] };
    const q = u.searchParams.get('request[search]');
    if (u.searchParams.get('action') === 'theme_information') {
      const slug = u.searchParams.get('request[slug]');
      const known = { herald: 'Herald Pro Magazine' }; // same folder name, different theme
      if (!known[slug]) throw new Error('HTTP 404');
      return { name: known[slug], slug, version: '3.0' };
    }
    if (u.pathname.startsWith('/themes')) {
      const themes = { Neve: 'neve', 'Twenty Twenty-Five': 'twentytwentyfive' };
      return { themes: themes[q] ? [{ name: q, slug: themes[q], version: '9' }, { name: q + ' Pro', slug: 'other' }] : [] };
    }
    const hit = Object.entries(pluginIndex).find(([n]) => normName(n) === normName(q));
    const latest = { akismet: '5.7.2', 'hello-dolly': '1.7.2' }; // wordpress.org's current release
    return { plugins: hit ? [{ name: hit[0], slug: hit[1], version: latest[hit[1]] ?? null }] : [{ name: 'Something else', slug: 'nope' }] };
  }
  const m = u.pathname.match(/^\/(core|php|plugin|theme)\/([^/]+)\/$/);
  if (m[1] === 'core') return { data: { vulnerability: m[2] === '7.1.3' ? [{ name: '7.1.3', source: [{ id: 'CVE-2026-119977', name: 'Core RCE' }], impact: [] }] : [] } };
  if (m[1] === 'php') return { data: { status: 's', date_end: '2027-12-31', vulnerability: [vuln('8.3.36', { impact: { cvss: { severity: 'c' }, ssvc: { kev: true } } })] } };
  return { data: vulnDb[`${m[1]}/${m[2]}`] ?? { vulnerability: null } };
}

test('full check sorts everything into the right groups', async () => {
  const info = parseSiteHealth(sample);
  const results = await checkSite(info, fakeFetch);
  const groups = Object.fromEntries(classify(results).map((e) => [e.item.name, e.group]));
  assert.deepEqual(groups, {
    WordPress: 'fix',
    PHP: 'host',
    'Akismet Anti-spam: Spam Protection': 'ok',
    'All-In-One Security (AIOS) – Security and Firewall': 'update',
    'The Events Calendar': 'fix',
    'Example Custom Plugin': 'unchecked',
    'Abandoned Gallery': 'ok', // WPVulnerability's closed flag is ignored (unreliable)
    'Hello Dolly': 'ok',
    'Old Snapshot': 'unchecked',
    'p3-profiler.php': 'unchecked',
    'Herald Mobile': 'unchecked',
    Herald: 'unchecked',
    Neve: 'remove',
    'Twenty Twenty-Five': 'update',
  });
  const tec = results.items.find((i) => i.name === 'The Events Calendar');
  assert.equal(tec.vulns.length, 1, 'the <6.18.2 record must not match 6.18.2');
  assert.equal(tec.vulns[0].fixedIn, '6.18.3');
  const php = classify(results).find((e) => e.group === 'host');
  assert.match(php.email, /PHP 8\.3\.35/);
  assert.match(php.email, /fixed in PHP 8\.3\.36/);
  assert.ok(results.php.vulns[0].exploited);
});

test('a vulnerability still present in the latest release counts as "no fix yet"', async () => {
  const text = sample.replace('Akismet Anti-spam: Spam Protection: version: 5.7.2, author: Automattic - Anti-spam Team, Auto-updates disabled',
    'Akismet Anti-spam: Spam Protection: version: 5.7.2, author: Automattic (latest version: 5.7.3), Auto-updates disabled');
  vulnDb['plugin/akismet'] = { name: 'Akismet', vulnerability: [{ ...vuln('x'), operator: { max_operator: 'le', max_version: '5.7.3', unfixed: 0 } }] };
  try {
    const results = await checkSite(parseSiteHealth(text), fakeFetch);
    const e = classify(results).find((x) => x.item.name.startsWith('Akismet'));
    assert.equal(e.group, 'nofix');
  } finally {
    vulnDb['plugin/akismet'] = { name: 'Akismet', vulnerability: [] };
  }
});

test('slug lookup refuses ambiguous or inexact names', async () => {
  const f = async () => ({ plugins: [{ name: 'Gallery', slug: 'a' }, { name: 'Gallery', slug: 'b' }] });
  assert.equal(await findSlug('plugin', 'Gallery', f), null);
  const g = async () => ({ plugins: [{ name: 'Gallery Pro', slug: 'a' }] });
  assert.equal(await findSlug('plugin', 'Gallery', g), null);
});

test('loose name matches need the version numbers to agree', async () => {
  const wpforms = async () => ({ plugins: [
    { name: 'WPForms &#8211; AI Form Builder for WordPress', slug: 'wpforms-lite', version: '2.0.4', author: '<a href="x">Syed Balkhi</a>' },
    { name: 'WP Mail SMTP by WPForms', slug: 'wp-mail-smtp', version: '4.10.3', author: 'Syed Balkhi' },
  ] });
  const item = parseItemLine('WPForms Lite: version: 2.0.3, author: WPForms (latest version: 2.0.4), Auto-updates disabled');
  assert.equal((await findSlug('plugin', item, wpforms))?.slug, 'wpforms-lite');
  const stale = { ...item, latest: '2.0.9' };
  assert.equal(await findSlug('plugin', stale, wpforms), null, 'version disagreement: refuse');

  const updraft = async () => ({ plugins: [
    { name: 'UpdraftPlus: WP Backup &amp; Migration Plugin', slug: 'updraftplus', version: '1.26.14', author: '<a href="x">David Anderson / Team Updraft</a>' },
    { name: 'All-In-One Security (AIOS) &#8211; Security and Firewall', slug: 'all-in-one-wp-security-and-firewall', version: '1.26.14', author: 'David Anderson / Team Updraft' },
  ] });
  const up = parseItemLine('UpdraftPlus - Backup/Restore: version: 1.26.14, author: TeamUpdraft, DavidAnderson, Auto-updates disabled');
  assert.equal(up.author, 'TeamUpdraft, DavidAnderson');
  assert.equal((await findSlug('plugin', up, updraft))?.slug, 'updraftplus');

  const kb = async () => ({ plugins: [{ name: 'Knowledge Base', slug: 'knowledgebase', version: '3.2.4', author: 'Ajay' }] });
  const kbItem = parseItemLine('WebberZone Knowledge Base: version: 3.2.2, author: WebberZone (latest version: 3.2.4), Auto-updates disabled');
  assert.equal((await findSlug('plugin', kbItem, kb))?.slug, 'knowledgebase');
});

test('an "unfixed" record whose own sources say <= 2.6.5 does not flag 2.7.4', () => {
  const rec = {
    operator: { max_operator: 'le', max_version: '2.7.4', unfixed: '1' },
    source: [
      { id: 'CVE-2026-65485', name: 'WordPress Content Control plugin <= 2.6.5 - Broken Access Control vulnerability' },
      { id: 'x', name: 'Content Control', description: 'vulnerable in versions up to, and including, 2.6.5.' },
    ],
  };
  assert.ok(contradictedBySources(rec, '2.7.4'));
  assert.equal(matchVulns([rec], '2.7.4').length, 0);
  assert.equal(matchVulns([rec], '2.6.5').length, 1);
  const vague = { ...rec, source: [{ id: 'y', name: 'Something without a version' }] };
  assert.equal(matchVulns([vague], '2.7.4').length, 1, 'no stated version: keep the warning');
});

test('MainWP Child beats MainWP Dashboard by name shape', async () => {
  const f = async () => ({ plugins: [
    { name: 'MainWP Child &#8211; Securely Connects to the MainWP Dashboard', slug: 'mainwp-child', version: '6.4.1', author: 'mainwp' },
    { name: 'MainWP Dashboard: Self-hosted WordPress Management', slug: 'mainwp', version: '6.4.1', author: 'mainwp' },
  ] });
  const item = parseItemLine('MainWP Child: version: 6.3, author: MainWP (latest version: 6.4.1), Auto-updates disabled');
  assert.equal((await findSlug('plugin', item, f))?.slug, 'mainwp-child');
});

test('host email for end-of-life PHP without listed vulns', () => {
  const t = hostEmail({ version: '8.1.30', branch: '8.1', endOfLife: true, vulns: [] });
  assert.match(t, /no longer receives security fixes/);
});

test('version text stops before "(latest version: …)" in either field order', () => {
  const p = parseItemLine('Old Snapshot: author: (undefined), version: 1.0.0 (latest version: 1.1), Auto-updates disabled');
  assert.equal(p.version, '1.0.0');
  assert.equal(p.latest, '1.1');
});

test('distribution PHP builds are reduced to the upstream number', () => {
  const info = parseSiteHealth(sample.replace('php_version: 8.3.35 64bit', 'php_version: 8.1.2-1ubuntu2.14 64bit'));
  assert.equal(info.php, '8.1.2');
  assert.equal(info.phpRaw, '8.1.2-1ubuntu2.14');
});

test('a failed WordPress or PHP lookup does not stop the plugin checks', async () => {
  const flaky = async (url) => {
    if (/wpvulnerability\.net\/(core|php)\//.test(url)) throw new Error('HTTP 404');
    return fakeFetch(url);
  };
  const results = await checkSite(parseSiteHealth(sample), flaky);
  const groups = Object.fromEntries(classify(results).map((e) => [e.item.name, e.group]));
  assert.equal(groups.WordPress, 'unchecked');
  assert.equal(groups.PHP, 'unchecked');
  assert.equal(groups['The Events Calendar'], 'fix');
});

test('a custom theme sharing a folder name with a wordpress.org theme is not matched', async () => {
  const results = await checkSite(parseSiteHealth(sample), fakeFetch);
  const herald = results.items.find((i) => i.name === 'Herald');
  assert.equal(herald.checked, false);
  assert.equal(herald.vulns.length, 0);
});

test('version comparison: leading v and trailing zeros', () => {
  assert.equal(compareVersions('v2.1.0', '2.0'), 1);
  assert.equal(compareVersions('2.0', '2.0.0'), 0);
  assert.ok(!affects('2.0', { max_operator: 'lt', max_version: '2.0.0', unfixed: 0 }));
});

test('bulletins link only while the installed version is below the fix', () => {
  const tec = { kind: 'plugin', slug: 'the-events-calendar', fixedIn: '6.18.3' };
  assert.ok(bulletinApplies(tec, { kind: 'plugin', slug: 'the-events-calendar', version: '6.18.2' }));
  assert.ok(!bulletinApplies(tec, { kind: 'plugin', slug: 'the-events-calendar', version: '6.18.3.1' }));
  assert.ok(!bulletinApplies(tec, { kind: 'plugin', slug: 'other', version: '1.0' }));
  const php = { kind: 'php', fixedIn: ['8.2.35', '8.3.36', '8.4.27', '8.5.12'] };
  assert.ok(bulletinApplies(php, { kind: 'php', version: '8.3.35' }));
  assert.ok(!bulletinApplies(php, { kind: 'php', version: '8.3.36' }));
  assert.ok(!bulletinApplies(php, { kind: 'php', version: '8.4.27' }));
  assert.ok(bulletinApplies(php, { kind: 'php', version: '8.1.30' }), 'older branch with no fix');
});
