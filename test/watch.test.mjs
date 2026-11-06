import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { matchCve, fromWpv, draftBulletin, groupFindings, isUrgent, phpBranchWatched } from '../watch/lib.mjs';
import { bulletinApplies } from '../site/lib.js';

const cve = (id) => JSON.parse(readFileSync(new URL(`./fixtures/cve/CVE-${id}.json`, import.meta.url), 'utf8'));
const watch = JSON.parse(readFileSync(new URL('../watch/watchlist.json', import.meta.url), 'utf8'));

test('watchlist entries are well-formed and unique', () => {
  const slugs = new Set();
  for (const p of [...watch.plugins, ...watch.themes]) {
    assert.match(p.slug, /^[a-z0-9-]+$/);
    assert.ok(p.name && p.name.length > 1);
    assert.ok(!slugs.has(p.slug), `duplicate ${p.slug}`);
    slugs.add(p.slug);
  }
  for (const b of watch.php) assert.match(b, /^\d+\.\d+$/);
});

test('official CVE records are matched to watched plugins, core and PHP', () => {
  const tec = matchCve(cve('2026-119370'), watch);
  assert.equal(tec.kind, 'plugin');
  assert.equal(tec.slug, 'the-events-calendar');
  assert.equal(tec.through, '6.18.2');
  assert.deepEqual(tec.cwes, ['CWE-79']);
  assert.equal(matchCve(cve('2026-54851'), watch).slug, 'wpforms-lite');
  const core = matchCve(cve('2026-119977'), watch);
  assert.equal(core.kind, 'core');
  assert.equal(core.through, '7.1.3');
  assert.equal(core.privileges, 'N');
  const php = matchCve(cve('2026-109618'), watch);
  assert.equal(php.kind, 'php');
  assert.ok(php.fixedIn.includes('8.3.36'));
  assert.ok(phpBranchWatched(php, watch.php));
});

test('CVEs for unwatched plugins are ignored', () => {
  const rec = cve('2026-119370');
  rec.containers.cna.affected[0].packageName = 'some-other-plugin';
  assert.equal(matchCve(rec, watch), null);
});

test('drafts use the current release as the fix when the record only says "X or lower"', () => {
  const f = matchCve(cve('2026-54851'), watch);
  const [g] = groupFindings([f], watch);
  g.current = '2.0.4';
  const d = draftBulletin(g, '2026-11-07');
  assert.equal(d.title, 'WPForms Lite: update to 2.0.4');
  assert.match(d.summary, /plant harmful code in pages/);
  assert.deepEqual(d.affects, [{ kind: 'plugin', slug: 'wpforms-lite', through: '2.0.3' }]);
  assert.ok(bulletinApplies(d.affects[0], { kind: 'plugin', slug: 'wpforms-lite', version: '2.0.3' }));
  assert.ok(!bulletinApplies(d.affects[0], { kind: 'plugin', slug: 'wpforms-lite', version: '2.0.4' }));
});

test('if even the current release is affected, the draft says there is no fix', () => {
  const f = matchCve(cve('2026-54851'), watch);
  const [g] = groupFindings([f], watch);
  g.current = '2.0.3';
  const d = draftBulletin(g, '2026-11-07');
  assert.match(d.title, /no fix yet/);
  assert.match(d.fix[0], /Deactivate/);
});

test('the official weakness category beats loose wording ("allows Code Injection")', () => {
  const f = matchCve(cve('2026-119370'), watch);
  f.description += ' This allows Code Injection.';
  const [g] = groupFindings([f], watch);
  g.current = '6.18.3.1';
  assert.match(draftBulletin(g, '2026-11-07').summary, /plant harmful code/);
});

test('no "the The" in summaries; core RCE without login is urgent', () => {
  const [g] = groupFindings([matchCve(cve('2026-119370'), watch)], watch);
  g.current = '6.18.3.1';
  assert.match(draftBulletin(g, '2026-11-07').summary, /in The Events Calendar plugin/);
  const core = groupFindings([matchCve(cve('2026-119977'), watch)], watch)[0];
  core.current = '7.1.4';
  const d = draftBulletin(core, '2026-11-07');
  assert.match(d.summary, /anyone on the internet, with no login/);
  assert.equal(d.title, 'WordPress 7.1.4: security release');
  assert.ok(isUrgent(core.vulns));
});

test('the same CVE from two sources is drafted once', () => {
  const a = matchCve(cve('2026-54851'), watch);
  const b = { ...a, source: 'wpvulnerability', id: 'uuid-1' };
  const groups = groupFindings([a, b], watch);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].vulns.length, 1);
});

test('an aggregator "unfixed" record whose sources say "<= 2.6.5" becomes "affected through 2.6.5"', () => {
  const rec = {
    uuid: 'u', name: 'Content Control <= 2.7.4 (unfixed)',
    operator: { max_operator: 'le', max_version: '2.7.4', unfixed: '1' },
    source: [{ id: 'CVE-2026-65485', name: 'WordPress Content Control plugin <= 2.6.5 - Broken Access Control vulnerability' }],
    impact: { cvss: { severity: 'm', pr: 'n' } },
  };
  const f = fromWpv(rec, 'plugin', 'content-control', 'Content Control');
  assert.equal(f.unfixed, false);
  assert.equal(f.through, '2.6.5');
});

test('a duplicate from WPVulnerability adds "Unauthenticated" to the CVE-only record', () => {
  const official = matchCve(cve('2026-54851'), watch);
  const wordfence = fromWpv({
    uuid: 'u2', operator: { max_operator: 'lt', max_version: '2.0.3.1', unfixed: 0 },
    source: [
      { id: 'CVE-2026-54851', name: 'CVE-2026-54851' },
      { id: 'ac8e', name: 'WPForms <= 2.0.3 - Unauthenticated Stored Cross-Site Scripting', link: 'https://www.wordfence.com/x' },
    ],
    impact: { cvss: { severity: 'h', pr: 'n' } },
  }, 'plugin', 'wpforms-lite', 'WPForms Lite');
  const [g] = groupFindings([official, wordfence], watch);
  g.current = '2.0.4';
  const d = draftBulletin(g, '2026-11-07');
  assert.match(d.summary, /anyone on the internet, with no login/);
  assert.ok(isUrgent(g.vulns));
  assert.ok(d.sources.includes('https://www.wordfence.com/x'));
});
