// Pure functions for the bulletin watcher: recognise new vulnerabilities for
// watched products (from the official CVE list and from WPVulnerability) and
// turn them into plain-language bulletin drafts. No network access here.

import { compareVersions, normName, contradictedBySources } from '../site/lib.js';

// ---------------------------------------------------------------------------
// Reading an official CVE record (CVE JSON 5, as published in CVEProject/cvelistV5)
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

function cvssOf(cna) {
  for (const m of cna.metrics || []) {
    const v = m.cvssV4_0 || m.cvssV3_1 || m.cvssV3_0 || m.cvssV3;
    if (v?.baseSeverity) return v;
  }
  return null;
}

// Which watched product does this CVE record affect? Returns null if none.
export function matchCve(record, watch) {
  const cna = record?.containers?.cna;
  if (!cna || record.cveMetadata?.state !== 'PUBLISHED') return null;
  const desc = (cna.descriptions || []).find((d) => d.lang?.startsWith('en'))?.value || '';
  for (const a of cna.affected || []) {
    const url = (a.collectionURL || '').toLowerCase();
    const pkg = (a.packageName || '').toLowerCase();
    let kind = null;
    let slug = null;
    if (url.includes('wordpress.org/plugins') && pkg) [kind, slug] = ['plugin', pkg];
    else if (url.includes('wordpress.org/themes') && pkg) [kind, slug] = ['theme', pkg];
    else if (/^wordpress( foundation)?$/i.test(a.vendor || '') && /^wordpress$/i.test(a.product || '')) kind = 'core';
    else if (/^php( group)?$/i.test(a.vendor || '') && /^php$/i.test(a.product || '')) kind = 'php';
    else if (/wordpress/i.test(desc)) {
      // Some CNAs leave out packageName: fall back to the exact product name.
      const p = watch.plugins.find((w) => normName(w.name) === normName(a.product || ''));
      const t = watch.themes.find((w) => normName(w.name) === normName(a.product || ''));
      if (p) [kind, slug] = ['plugin', p.slug];
      else if (t) [kind, slug] = ['theme', t.slug];
    }
    if (!kind) continue;
    if (kind === 'plugin' && !watch.plugins.some((w) => w.slug === slug)) continue;
    if (kind === 'theme' && !watch.themes.some((w) => w.slug === slug)) continue;
    if (kind === 'core' && !watch.core) continue;
    if (kind === 'php' && !(watch.php || []).length) continue;

    const ranges = (a.versions || []).filter((v) => v.status === 'affected');
    const fixes = ranges.map((v) => v.lessThan).filter((x) => x && !/[*x]/i.test(x));
    const through = ranges.map((v) => v.lessThanOrEqual).filter(Boolean);
    const cvss = cvssOf(cna);
    return {
      source: 'cve',
      id: record.cveMetadata.cveId,
      cves: [record.cveMetadata.cveId],
      kind,
      slug,
      name: kind === 'core' ? 'WordPress' : kind === 'php' ? 'PHP' : a.product,
      title: cna.title || desc.split('. ')[0],
      description: desc,
      cwes: (cna.problemTypes || []).flatMap((p) => p.descriptions || []).map((d) => d.cweId).filter(Boolean),
      privileges: cvss?.privilegesRequired || (cvss?.vectorString || '').match(/PR:([NLH])/)?.[1] || null,
      severity: cvss ? String(cvss.baseSeverity).toLowerCase() : null,
      exploited: false,
      fixedIn: fixes.length ? fixes : [],
      through: through.length ? through.sort(compareVersions).pop() : null,
      unfixed: false,
      published: (record.cveMetadata.datePublished || '').slice(0, 10),
      links: [`https://www.cve.org/CVERecord?id=${record.cveMetadata.cveId}`],
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Reading a WPVulnerability record
// ---------------------------------------------------------------------------

const SEV = { c: 'critical', h: 'high', m: 'medium', l: 'low' };

export function fromWpv(rec, kind, slug, name) {
  const impact = rec.impact && !Array.isArray(rec.impact) ? rec.impact : {};
  const op = rec.operator || {};
  const sources = rec.source || [];
  const named = sources.find((s) => !/^CVE-/.test(s.id)) || sources[0] || {};
  const text = sources.map((s) => `${s.name || ''} ${s.description || ''}`).join(' ');
  const pr = (impact.cvss?.pr || '').toUpperCase();
  // An "unfixed" record whose own sources all name a last affected version is
  // really "fixed after that version" (the aggregator stretched the range).
  let unfixed = String(op.unfixed) === '1';
  let through = op.max_operator === 'le' ? op.max_version : null;
  if (unfixed && contradictedBySources(rec, '999999')) {
    unfixed = false;
    const stated = [...text.matchAll(/(?:<=\s*|up to,? and including,?\s*|through\s+)v?(\d+(?:\.\d+)+)/gi)].map((m) => m[1]);
    through = stated.sort(compareVersions).pop() || null;
  }
  return {
    source: 'wpvulnerability',
    id: rec.uuid,
    cves: sources.map((s) => s.id).filter((id) => /^CVE-/.test(id)),
    kind,
    slug,
    name,
    title: named.name || rec.name,
    description: named.description || '',
    cwes: [],
    text,
    privileges: pr === 'N' || pr === 'L' || pr === 'H' ? pr : null,
    severity: SEV[impact.cvss?.severity] || null,
    exploited: Boolean(impact.ssvc?.kev) || impact.ssvc?.exploitation === 'active',
    fixedIn: op.max_operator === 'lt' && op.max_version && !unfixed ? [op.max_version] : [],
    through,
    unfixed,
    published: (sources.map((s) => s.date).filter(Boolean).sort()[0] || '').slice(0, 10),
    links: sources.map((s) => s.link).filter((l) => /^https:\/\//.test(l || '')),
  };
}

// ---------------------------------------------------------------------------
// Plain-language drafting
// ---------------------------------------------------------------------------

const EFFECTS = [
  { re: /CWE-(94|95|77|78|434|502)\b|remote code execution|code injection|command injection|arbitrary file upload|object injection/i,
    text: 'let someone run their own code on the server, which amounts to taking over the site', rank: 6 },
  { re: /CWE-89\b|sql injection/i, text: 'let someone read or change the site\'s database', rank: 5 },
  { re: /CWE-(269|287|288|306|639)\b|privilege escalation|authentication bypass|account takeover/i,
    text: 'let someone take over accounts or give themselves more power on the site', rank: 5 },
  { re: /CWE-(22|23|73|98)\b|path traversal|directory traversal|arbitrary file (read|deletion|download)|local file inclusion/i,
    text: 'let someone read or delete files on the server', rank: 4 },
  { re: /CWE-918\b|server-side request forgery|ssrf/i, text: 'let someone make the server send requests on their behalf', rank: 3 },
  { re: /CWE-79\b|cross[- ]site scripting|xss/i, text: 'let someone plant harmful code in pages that visitors then load', rank: 3 },
  { re: /CWE-(284|285|862|863)\b|missing authori[sz]ation|broken access control|unauthori[sz]ed/i,
    text: 'let someone do things their account shouldn\'t be allowed to do', rank: 3 },
  { re: /CWE-352\b|cross[- ]site request forgery|csrf/i,
    text: 'let an attacker trick a logged-in administrator into making changes by getting them to click a link', rank: 2 },
  { re: /CWE-(200|201|359|532)\b|information (disclosure|exposure)|sensitive information/i,
    text: 'let someone see information that should be private', rank: 2 },
  { re: /CWE-601\b|open redirect/i, text: 'let someone send visitors to a harmful site using a link that looks like yours', rank: 1 },
  { re: /denial of service|CWE-(400|770|1333)\b|redos/i, text: 'let someone slow the site down or knock it offline', rank: 1 },
];

// The official weakness category (CWE) wins when present: some databases
// describe ordinary cross-site scripting as "allows Code Injection".
function effectOf(v) {
  if (v.cwes.length) {
    const byCwe = EFFECTS.find((e) => e.re.test(v.cwes.join(' ')));
    if (byCwe) return byCwe;
  }
  const hay = `${v.title} ${v.description} ${v.text || ''}`;
  return EFFECTS.find((e) => e.re.test(hay)) || { text: 'cause a security problem', rank: 0 };
}

function whoOf(v) {
  const t = `${v.title} ${v.description} ${v.text || ''}`;
  const role = t.match(/\((Subscriber|Contributor|Author|Editor|Shop Manager|Administrator)\+\)/i)?.[1];
  if (/unauthenticated/i.test(t) || (!role && v.privileges === 'N')) return { text: 'anyone on the internet, with no login', rank: 3 };
  if (role && /subscriber|customer/i.test(role)) return { text: 'anyone with an account on the site, even a basic Subscriber', rank: 2 };
  if (role && /administrator/i.test(role)) return { text: 'only an Administrator, so the risk is lower', rank: 0 };
  if (role) return { text: `anyone with a ${role[0].toUpperCase() + role.slice(1).toLowerCase()} account or higher`, rank: 1 };
  if (v.privileges === 'L') return { text: 'anyone with an account on the site', rank: 2 };
  if (v.privileges === 'H') return { text: 'only someone with an administrator-level account, so the risk is lower', rank: 0 };
  return null;
}

function maxSeverity(vs) {
  let best = 'medium';
  let seen = false;
  for (const v of vs) {
    if (!v.severity || !SEVERITY_ORDER.includes(v.severity)) continue;
    if (!seen || SEVERITY_ORDER.indexOf(v.severity) > SEVERITY_ORDER.indexOf(best)) best = v.severity;
    seen = true;
  }
  if (vs.some((v) => v.exploited)) return 'critical';
  return best;
}

export function isUrgent(vs) {
  return vs.some((v) => v.exploited || v.severity === 'critical' || whoOf(v)?.rank === 3);
}

const NUM = ['no', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten'];

// One bulletin per product per run, covering every new vulnerability found for it.
export function draftBulletin(group, today) {
  const { kind, slug, name } = group;
  const vs = group.vulns;
  const worst = [...vs].sort((a, b) => effectOf(b).rank - effectOf(a).rank || (whoOf(b)?.rank ?? -1) - (whoOf(a)?.rank ?? -1))[0];
  const effect = effectOf(worst).text;
  const who = whoOf(worst);
  const n = vs.length;
  const count = n <= 10 ? NUM[n] : String(n);
  const allFixes = [...new Set(vs.flatMap((v) => v.fixedIn))].sort(compareVersions);
  const through = vs.map((v) => v.through).filter(Boolean).sort(compareVersions).pop() || null;
  // Records that only say "X or lower" get the product's current release as the
  // fix, if it is newer than X; if even the current release is affected, there
  // is no fix yet.
  let fixed = kind === 'php' ? allFixes : allFixes.length ? allFixes[allFixes.length - 1] : null;
  let fixIsCurrent = false;
  let anyUnfixed = vs.some((v) => v.unfixed);
  if (kind !== 'php' && !anyUnfixed && through && group.current) {
    if (compareVersions(group.current, through) > 0) {
      if (!fixed || compareVersions(fixed, through) <= 0) {
        fixed = group.current;
        fixIsCurrent = true;
      }
    } else if (!fixed || compareVersions(fixed, through) <= 0) {
      anyUnfixed = true;
    }
  }
  const exploited = vs.some((v) => v.exploited);

  const thing = kind === 'core' ? 'WordPress itself' : kind === 'php' ? 'PHP, which runs on your host\'s server'
    : /^the /i.test(name) ? `${name} ${kind}` : `the ${name} ${kind}`;
  let summary = `${count} new security problem${n > 1 ? 's' : ''} in ${thing}. ` +
    `The most serious could ${effect}` + (who ? `, and can be used by ${who.text}` : '') + '.';
  if (exploited) summary += ' Attackers are already using it.';
  if (kind === 'php') summary += ' Your host has to fix this one.';

  const where = kind === 'theme' ? 'Appearance → Themes' : 'Plugins → Installed Plugins';
  let title;
  let check;
  let fix;
  const affectedLine = through
    ? `Version ${through} or lower is affected.`
    : fixed && kind !== 'php' ? `Any version older than ${fixed} is affected.` : null;

  if (kind === 'core') {
    const noFix = anyUnfixed || (!fixed && !through);
    title = fixed ? `WordPress ${fixed}: security release` : noFix ? 'WordPress: security problem, no fix yet' : `WordPress: update past ${through}`;
    check = ['Go to Dashboard → Updates.', 'The page says "You have the latest version of WordPress" when you are up to date.',
      through ? `Version ${through} or lower is affected. Older WordPress branches get their own fixed releases.` : null].filter(Boolean);
    fix = noFix
      ? ['There is no fixed release yet. Keep WordPress updated and watch this page.']
      : ['Make a backup first.', `Go to Dashboard → Updates and click "Update to version ${fixed || '…'}" (the newest offered).`, 'Most sites update themselves automatically for security releases. Check anyway.'];
  } else if (kind === 'php') {
    title = 'PHP: ask your host to confirm PHP is patched';
    check = ['Go to Tools → Site Health → Info and open the "Server" section.', 'Read the "PHP version" line.',
      allFixes.length ? `Fixed versions: ${allFixes.join(', ')} or later on the same branch.` : 'No fixed versions are listed yet.'];
    fix = ['Open a support ticket with your host. The checker on this page writes the message for you.',
      'If your control panel has a "PHP Selector" or "PHP version" setting, pick the newest version on your current branch.',
      'After any PHP change, open your home page and one inner page to check they still load.'];
  } else if (anyUnfixed) {
    title = `${name}: no fix yet, turn it off`;
    check = [`Go to ${where}.`, `Look for "${name}". If it's there, you are affected.`];
    fix = kind === 'theme'
      ? ['If it is your active theme, contact your kingdom webministry for help choosing a replacement.', 'If it is not active, click it, then "Delete".']
      : [`On the same screen, click "Deactivate" under "${name}", then check your site still works.`,
          'If you don\'t need it, click "Delete". If you do, check back here for an update.'];
  } else {
    title = fixed ? `${name}: update to ${fixed}${fixIsCurrent ? '' : ' or later'}` : `${name}: update to the latest version (newer than ${through})`;
    check = [`Go to ${where}.`, `Find "${name}" and read the version number under its name.`, affectedLine].filter(Boolean);
    fix = kind === 'theme'
      ? ['Make a backup first.', `Click "${name}", then "Update now".`, 'Open your home page afterwards to check it still looks right.']
      : ['Make a backup first.', `On the same screen, click "update now" under "${name}".`, 'Open a page that uses it afterwards to check it still works.'];
  }

  const technical = vs
    .map((v) => `${v.cves.length ? v.cves.join(', ') + ': ' : ''}${v.title}${v.fixedIn.length ? ` (fixed in ${v.fixedIn.join(', ')})` : v.unfixed ? ' (no fix yet)' : ''}`)
    .join(' · ');
  const sources = [...new Set(vs.flatMap((v) => v.links))].slice(0, 6);
  if (kind === 'plugin' && slug) sources.push(`https://wordpress.org/plugins/${slug}/`);
  if (kind === 'theme' && slug) sources.push(`https://wordpress.org/themes/${slug}/`);

  return {
    id: `${today}-${slug || kind}`,
    date: today,
    severity: maxSeverity(vs),
    title,
    summary,
    affects: [{ kind, ...(slug ? { slug } : {}), ...(fixed && !fixIsCurrent ? { fixedIn: fixed } : {}), ...(through ? { through } : {}) }],
    check,
    fix,
    help: 'If the update fails, or something looks wrong afterwards, contact your kingdom webministry.',
    technical,
    sources: [...new Set(sources)],
  };
}

// Group findings by product, dropping duplicates of the same CVE seen from both sources.
export function groupFindings(findings, watch) {
  const groups = new Map();
  const seenCves = new Set();
  const byCve = new Map();
  for (const f of findings) {
    if (f.cves.length && f.cves.every((c) => seenCves.has(c))) {
      // Same bug from another source: keep what that source adds. The official
      // CVE often omits who can use it; Wordfence's entry says "Unauthenticated".
      const first = byCve.get(f.cves.find((c) => byCve.has(c)));
      if (first) {
        first.privileges = first.privileges || f.privileges;
        first.severity = first.severity || f.severity;
        first.exploited = first.exploited || f.exploited;
        first.text = `${first.text || ''} ${f.title} ${f.description} ${f.text || ''}`;
        first.links = [...new Set([...first.links, ...f.links])];
        if (!first.fixedIn.length && f.fixedIn.length) first.fixedIn = f.fixedIn;
        first.through = first.through || f.through;
      }
      continue;
    }
    f.cves.forEach((c) => { seenCves.add(c); byCve.set(c, f); });
    const key = `${f.kind}/${f.slug || ''}`;
    if (!groups.has(key)) {
      const listed = f.kind === 'plugin' ? watch.plugins.find((w) => w.slug === f.slug) : f.kind === 'theme' ? watch.themes.find((w) => w.slug === f.slug) : null;
      groups.set(key, { kind: f.kind, slug: f.slug, name: listed?.name || f.name, vulns: [] });
    }
    groups.get(key).vulns.push(f);
  }
  return [...groups.values()];
}

// Is a PHP finding on a branch we watch? (CVE ranges are "8.3.*" style.)
export function phpBranchWatched(f, branches) {
  if (f.kind !== 'php') return true;
  if (!f.fixedIn.length) return true;
  return f.fixedIn.some((v) => branches.some((b) => v.startsWith(b + '.')));
}
