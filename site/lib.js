// Core logic for the Webminister Site Check. No DOM access here, so the
// tests can run it under Node. Everything runs in the visitor's browser;
// only component names and versions are sent to the public lookup services.

export const VULN_API = 'https://www.wpvulnerability.net';
export const WPORG_API = 'https://api.wordpress.org';

// ---------------------------------------------------------------------------
// Parsing the "Copy site info to clipboard" text from Tools > Site Health > Info
// ---------------------------------------------------------------------------

function parseSections(text) {
  const sections = {};
  let current = null;
  for (const raw of text.replace(/\r/g, '').split('\n')) {
    const line = raw.replace(/^`+|`+$/g, '').trimEnd();
    const head = line.match(/^###\s+([a-z0-9_-]+)(?:\s+\(\d+\))?\s+###$/i);
    if (head) {
      current = head[1].toLowerCase();
      sections[current] = [];
      continue;
    }
    if (current && line.trim()) sections[current].push(line);
  }
  return sections;
}

function keyValues(lines = []) {
  const out = {};
  for (const line of lines) {
    const m = line.match(/^\s*([A-Za-z0-9_.-]+):\s?(.*)$/);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

const UNDEF = /^\(?undefined\)?$/i;

// One plugin or theme line, e.g.
// "Akismet Anti-spam: Spam Protection: version: 5.7.2, author: Automattic (latest version: 5.8), Auto-updates disabled"
// "Some Plugin: author: (undefined), version: 1.0.0, Auto-updates disabled"
export function parseItemLine(line) {
  const idx = [': version: ', ': author: ']
    .map((k) => line.indexOf(k))
    .filter((i) => i >= 0);
  if (!idx.length) return null;
  const cut = Math.min(...idx);
  const name = line.slice(0, cut).trim();
  const rest = line.slice(cut + 2);
  const version = (rest.match(/(?:^|,\s*)version:\s*([^,]+)/) || [])[1]?.trim();
  const latest = (rest.match(/\(latest version:\s*([^)]+)\)/) || [])[1]?.trim();
  const auto = (rest.match(/Auto-updates (enabled|disabled)/i) || [])[1];
  const author = (rest.match(/author:\s*(.*?)(?:\s*\(latest version:[^)]*\))?(?:,\s*(?:version:|Auto-updates)|$)/) || [])[1];
  return {
    name,
    version: version && !UNDEF.test(version) ? version : null,
    latest: latest || null,
    author: author && !UNDEF.test(author) ? author.trim() : null,
    autoUpdates: auto ? auto.toLowerCase() === 'enabled' : null,
  };
}

function parseActiveTheme(lines) {
  const kv = keyValues(lines);
  if (!kv.name || /^none$/i.test(kv.name)) return null;
  const m = kv.name.match(/^(.*?)\s*\(([^()]+)\)\s*$/);
  const latest = (kv.version || '').match(/\(latest version:\s*([^)]+)\)/);
  return {
    name: m ? m[1] : kv.name,
    slug: m ? m[2] : null,
    version: (kv.version || '').replace(/\s*\(.*\)$/, '') || null,
    latest: latest ? latest[1].trim() : null,
    autoUpdates: kv.auto_update ? /enabled/i.test(kv.auto_update) : null,
  };
}

export function parseSiteHealth(text) {
  const s = parseSections(text || '');
  if (!s['wp-core']) {
    throw new Error(
      'This does not look like Site Health info. In WordPress go to Tools → Site Health → Info and click "Copy site info to clipboard", then paste here.'
    );
  }
  const core = keyValues(s['wp-core']);
  const server = keyValues(s['wp-server']);
  const db = keyValues(s['wp-database']);
  const items = [];

  const add = (kind, status, parsed) => {
    if (parsed) items.push({ kind, status, ...parsed });
  };
  for (const l of s['wp-plugins-active'] || []) add('plugin', 'active', parseItemLine(l));
  for (const l of s['wp-plugins-inactive'] || []) add('plugin', 'inactive', parseItemLine(l));
  for (const l of s['wp-mu-plugins'] || []) add('mu-plugin', 'active', parseItemLine(l));
  add('theme', 'active', parseActiveTheme(s['wp-active-theme']));
  add('theme', 'parent', parseActiveTheme(s['wp-parent-theme']));
  for (const l of s['wp-themes-inactive'] || []) add('theme', 'inactive', parseItemLine(l));

  return {
    wordpress: core.version || null,
    multisite: core.multisite === 'true',
    userRegistration: core.user_registration === '1',
    php: (server.php_version || '').split(/\s+/)[0] || null,
    database: db.server_version || null,
    items,
  };
}

// ---------------------------------------------------------------------------
// Version comparison (close to PHP's version_compare)
// ---------------------------------------------------------------------------

const SPECIAL = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, rc: 3, '#': 4, pl: 5, p: 5 };

function canon(v) {
  return String(v)
    .trim()
    .replace(/[-_+]/g, '.')
    .replace(/([^.\d]+)/g, '.$1.')
    .split('.')
    .filter(Boolean);
}

function cmpPart(a, b) {
  const na = /^\d+$/.test(a);
  const nb = /^\d+$/.test(b);
  if (na && nb) return Math.sign(Number(a) - Number(b));
  if (!na && !nb) return Math.sign((SPECIAL[a.toLowerCase()] ?? -1) - (SPECIAL[b.toLowerCase()] ?? -1));
  // number beats a pre-release word ("1.0.1" > "1.0.rc1"), loses to "pl"
  const word = na ? b : a;
  const r = (SPECIAL[word.toLowerCase()] ?? -1) >= SPECIAL.pl ? -1 : 1;
  return na ? r : -r;
}

export function compareVersions(a, b) {
  const pa = canon(a);
  const pb = canon(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    if (pa[i] === undefined) return /^\d+$/.test(pb[i]) ? -1 : 1;
    if (pb[i] === undefined) return /^\d+$/.test(pa[i]) ? 1 : -1;
    const c = cmpPart(pa[i], pb[i]);
    if (c) return c;
  }
  return 0;
}

function opHolds(version, op, bound) {
  if (!op || bound == null || bound === '') return true;
  const c = compareVersions(version, bound);
  switch (op) {
    case 'lt': return c < 0;
    case 'le': return c <= 0;
    case 'eq': return c === 0;
    case 'ge': return c >= 0;
    case 'gt': return c > 0;
    default: return false;
  }
}

// Does one WPVulnerability record apply to this installed version?
// perVersion: the endpoint already answered for this exact version (WordPress core),
// so a record without an operator applies. Elsewhere a record we can't range-check is skipped.
export function affects(version, operator, perVersion = false) {
  if (!operator) return perVersion;
  if (!version) return false;
  if (String(operator.unfixed) === '1' && !operator.max_version) {
    return opHolds(version, operator.min_operator, operator.min_version);
  }
  return (
    opHolds(version, operator.min_operator, operator.min_version) &&
    opHolds(version, operator.max_operator, operator.max_version)
  );
}

export function fixedIn(operator) {
  if (!operator || String(operator.unfixed) === '1') return null;
  if (operator.max_operator === 'lt') return operator.max_version;
  return null; // "le"/"eq": the fix is "a version later than max" — use the latest release
}

const SEV = { c: 'critical', h: 'high', m: 'medium', l: 'low' };

function summarize(rec, version) {
  const impact = rec.impact && !Array.isArray(rec.impact) ? rec.impact : {};
  const sevCode = impact.cvss?.severity || impact.cvss3?.severity;
  const severity = SEV[sevCode] || sevCode || null;
  const cves = (rec.source || []).map((s) => s.id).filter((id) => /^CVE-/.test(id));
  const best = (rec.source || []).find((s) => !/^CVE-/.test(s.id)) || (rec.source || [])[0] || {};
  return {
    title: best.name || rec.name || 'Known vulnerability',
    link: best.link || null,
    cves,
    severity,
    exploited: Boolean(impact.ssvc?.kev) || impact.ssvc?.exploitation === 'active',
    fixedIn: fixedIn(rec.operator),
    unfixed: String(rec.operator?.unfixed) === '1',
    installed: version,
    operator: rec.operator || null,
  };
}

// The aggregator sometimes marks an old issue "unfixed" and stretches its range
// to the newest release, while every source it cites says "<= 2.6.5". When all
// sources that state a version put it below what is installed, trust them.
const STATED = /(?:<=\s*|up to,? and including,?\s*|through\s+)v?(\d+(?:\.\d+)+)/gi;
export function contradictedBySources(rec, version) {
  if (String(rec.operator?.unfixed) !== '1') return false;
  const stated = [];
  for (const src of rec.source || []) {
    const text = `${src.name || ''} ${src.description || ''}`;
    const found = [...text.matchAll(STATED)].map((m) => m[1]);
    if (!found.length) return false; // a source with no stated version: can't overrule
    stated.push(found.sort(compareVersions).pop());
  }
  return stated.length > 0 && stated.every((v) => compareVersions(version, v) > 0);
}

export function matchVulns(records, version, perVersion = false) {
  return (records || [])
    .filter((r) => affects(version, r.operator, perVersion) && !contradictedBySources(r, version))
    .map((r) => summarize(r, version));
}

// ---------------------------------------------------------------------------
// Looking things up
// ---------------------------------------------------------------------------

function decodeEntities(s) {
  return String(s)
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#039;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

export function normName(s) {
  return decodeEntities(s)
    .toLowerCase()
    .replace(/[‐-―]/g, '-')
    .replace(/\s+/g, ' ')
    .trim();
}

function slugify(s) {
  return normName(s).replace(/&/g, ' ').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function squash(s) {
  return normName(s).replace(/<[^>]+>/g, '').replace(/[^a-z0-9]+/g, '');
}

// Same people? "TeamUpdraft, DavidAnderson" vs "David Anderson / Team Updraft".
function sameAuthor(pasted, wporg) {
  if (!pasted || !wporg) return false;
  const theirs = squash(wporg);
  const ours = normName(pasted).split(/,|&|\band\b/).map(squash).filter((x) => x.length > 2);
  return ours.length > 0 && ours.some((a) => theirs.includes(a));
}

// Find the wordpress.org slug for an installed plugin/theme.
//
// Site Health lists the name from the plugin's own header, which often differs
// from its wordpress.org listing ("WPForms Lite" vs "WPForms – AI Form Builder…").
// We accept a candidate when the names match exactly, or when a weaker name
// signal (prefix, suffix, folder-style slug, same author + first word) is backed
// by the version numbers: Site Health's "latest version" comes from
// wordpress.org itself, so it must equal the listing's version (or, with no
// update pending, the installed version must). Anything else returns null:
// "couldn't check" is better than a confident wrong answer.
export async function findSlug(kind, item, fetchJson) {
  const name = typeof item === 'string' ? item : item.name;
  const action = kind === 'theme' ? 'themes/info/1.2/?action=query_themes' : 'plugins/info/1.2/?action=query_plugins';
  const listKey = kind === 'theme' ? 'themes' : 'plugins';
  const url = `${WPORG_API}/${action}&request[search]=${encodeURIComponent(name)}&request[per_page]=20` +
    '&request[fields][description]=0&request[fields][sections]=0&request[fields][short_description]=0';
  const data = await fetchJson(url);
  const list = data?.[listKey] || [];
  const want = normName(name);

  const exact = [...new Set(list.filter((p) => normName(p.name) === want).map((p) => p.slug))];
  if (exact.length === 1) {
    const hit = list.find((p) => p.slug === exact[0]);
    return { slug: hit.slug, latest: hit.version || null, how: 'name' };
  }
  if (exact.length > 1 || typeof item === 'string') return null;

  const firstWord = want.split(/[\s:–-]+/).find((w) => w.length > 2);
  const versionAgrees = (p) =>
    p.version && (item.latest ? compareVersions(item.latest, p.version) === 0 : compareVersions(item.version, p.version) === 0);
  const nameSignal = (p) => {
    const theirs = normName(p.name);
    return (
      (theirs.startsWith(want + ' ') && /^[\s]*[–—:|(-]/.test(theirs.slice(want.length))) ||
      (theirs.length > 3 && want.endsWith(' ' + theirs)) ||
      slugify(name) === p.slug
    );
  };
  const authorSignal = (p) => {
    const author = typeof p.author === 'string' ? p.author : p.author?.display_name || p.author?.user_nicename;
    return sameAuthor(item.author, author) && firstWord && normName(p.name).includes(firstWord);
  };
  // Name-shape signals beat "same author": MainWP Child and MainWP Dashboard share
  // an author and a version number, but only one is named "MainWP Child – …".
  for (const tier of [nameSignal, authorSignal]) {
    const strong = list.filter((p) => tier(p) && versionAgrees(p));
    const slugs = [...new Set(strong.map((p) => p.slug))];
    if (slugs.length === 1) return { slug: slugs[0], latest: strong[0].version || null, how: 'name+version' };
    if (slugs.length > 1) return null;
  }
  return null;
}

const CUSTOM_HINT = 'Not listed on wordpress.org (custom, premium or host-installed), so it can\'t be checked here.';

async function checkItem(item, fetchJson) {
  const result = { ...item, vulns: [], closed: null, slug: item.slug || null, checked: false, note: null };
  if (item.kind === 'mu-plugin') {
    result.note = 'Must-use plugin: a file WordPress always loads. It can\'t be checked here; ask whoever installed it what it does.';
    return result;
  }
  if (!item.version) {
    result.note = 'No version number, so it can\'t be checked.';
    return result;
  }
  let latest = item.latest;
  if (!result.slug) {
    const found = await findSlug(item.kind, item, fetchJson);
    if (!found) {
      result.note = CUSTOM_HINT;
      return result;
    }
    result.slug = found.slug;
    result.matchedBy = found.how;
    latest = latest || found.latest;
  }
  const data = (await fetchJson(`${VULN_API}/${item.kind}/${encodeURIComponent(result.slug)}/`))?.data;
  if (!data || (!data.name && !data.vulnerability)) {
    // An unknown slug (e.g. a custom theme whose folder name isn't on wordpress.org)
    result.note = CUSTOM_HINT;
    return result;
  }
  result.checked = true;
  // (WPVulnerability's "latest" is a timestamp and its "closed" flag marks live
  // plugins such as bbPress as closed, so neither is used.)
  result.latest = latest || null;
  result.vulns = matchVulns(data.vulnerability, item.version);
  return result;
}

export async function checkSite(info, fetchJson, onProgress = () => {}) {
  const total = info.items.length + 2;
  let done = 0;
  const tick = (label) => onProgress(++done, total, label);

  const coreLatest = await fetchJson(`${WPORG_API}/core/version-check/1.7/`).then(
    (d) => d?.offers?.[0]?.current || null,
    () => null
  );
  const coreData = info.wordpress
    ? (await fetchJson(`${VULN_API}/core/${encodeURIComponent(info.wordpress)}/`))?.data
    : null;
  const core = {
    kind: 'core',
    name: 'WordPress',
    version: info.wordpress,
    latest: coreLatest,
    checked: Boolean(coreData),
    vulns: coreData ? matchVulns(coreData.vulnerability, info.wordpress, true) : [],
  };
  tick('WordPress');

  let php = null;
  if (info.php) {
    const branch = info.php.split('.').slice(0, 2).join('.');
    const data = (await fetchJson(`${VULN_API}/php/${encodeURIComponent(info.php)}/`))?.data;
    php = {
      kind: 'php',
      name: 'PHP',
      version: info.php,
      branch,
      checked: Boolean(data),
      endOfLife: data?.status === 'd' || (data?.date_end && new Date(data.date_end) < new Date()) || false,
      supportEnds: data?.date_end || null,
      vulns: data ? matchVulns(data.vulnerability, info.php) : [],
    };
  }
  tick('PHP');

  const items = [];
  for (const item of info.items) {
    try {
      items.push(await checkItem(item, fetchJson));
    } catch (e) {
      items.push({ ...item, vulns: [], checked: false, note: 'Lookup failed (' + e.message + '). Try again later.' });
    }
    tick(item.name);
  }
  return { core, php, items, userRegistration: info.userRegistration };
}

// ---------------------------------------------------------------------------
// Turning results into plain-language actions
// ---------------------------------------------------------------------------

export const GROUPS = [
  { id: 'fix', title: 'Fix now', blurb: 'Known security problems with a fix available.' },
  { id: 'nofix', title: 'Turn off: no fix yet', blurb: 'Known security problems the maker hasn\'t fixed.' },
  { id: 'remove', title: 'Remove', blurb: 'Not in use, or no longer maintained. Deleting is the simplest fix.' },
  { id: 'host', title: 'Ask your host', blurb: 'Server software you can\'t change yourself.' },
  { id: 'update', title: 'Update when you can', blurb: 'Behind the latest version, but nothing known is wrong.' },
  { id: 'unchecked', title: 'Couldn\'t check', blurb: 'Not on wordpress.org, so check with whoever made it.' },
  { id: 'ok', title: 'Looks fine', blurb: 'Up to date with nothing known.' },
];

const where = {
  plugin: 'Plugins → Installed Plugins',
  theme: 'Appearance → Themes',
};

function updateSteps(r) {
  if (r.kind === 'core') {
    return [
      'Make a backup first (UpdraftPlus or your host\'s backup tool).',
      `Go to Dashboard → Updates and click "Update to version ${r.latest || 'the latest version'}".`,
      'Afterwards, open your home page and one inner page to check they still load.',
    ];
  }
  if (r.kind === 'theme') {
    return [
      'Make a backup first.',
      `Go to ${where.theme}, click "${r.name}", then click "Update now".`,
      'If there is no Update button, the theme came from outside wordpress.org: download the new version from its maker.',
    ];
  }
  return [
    'Make a backup first.',
    `Go to ${where.plugin}, find "${r.name}" and click "update now" under it.`,
    'If there is no update link, the plugin came from outside wordpress.org: get the new version from its maker.',
  ];
}

function removeSteps(r) {
  if (r.kind === 'theme') {
    if (r.status !== 'inactive') {
      return [`"${r.name}" is your active theme (or its parent), so it can't simply be deleted. Ask your kingdom webministry for help choosing a replacement.`];
    }
    return [
      `Go to ${where.theme}, click "${r.name}" to open its details.`,
      'Click "Delete" in the bottom-right corner and confirm.',
      'Keep at least one default "Twenty Twenty-something" theme installed as a fallback.',
    ];
  }
  return [
    `Go to ${where.plugin} and find "${r.name}".`,
    r.status === 'active' ? 'Click "Deactivate", then check the site still works.' : null,
    'Click "Delete" and confirm.',
  ].filter(Boolean);
}

export function classify(results) {
  const out = [];
  const push = (group, r, extra) => out.push({ group, item: r, ...extra });

  const { core, php } = results;
  if (core) {
    if (core.vulns.length) push('fix', core, { steps: updateSteps(core) });
    else if (core.latest && compareVersions(core.version, core.latest) < 0) push('update', core, { steps: updateSteps(core) });
    else push('ok', core);
  }

  if (php) {
    if (php.vulns.length || php.endOfLife) {
      push('host', php, {
        steps: [
          'Send your host the email below (or open a support ticket with the same text).',
          'Some hosts patch PHP without changing the version number, so they may tell you it is already fixed. That answer is fine.',
        ],
        email: hostEmail(php),
      });
    } else push('ok', php);
  }

  for (const r of results.items) {
    if (!r.checked) {
      push('unchecked', r, { note: r.note });
      continue;
    }
    const vulnerable = r.vulns.length > 0;
    // "No fix yet": the maker marked it unfixed, or even the latest release is still affected.
    const anyUnfixed = r.vulns.some(
      (v) => v.unfixed || (r.latest && v.operator && affects(r.latest, v.operator))
    );
    const inactive = r.status === 'inactive';
    const behind = r.latest && compareVersions(r.version, r.latest) < 0;
    // An outdated default theme is worth keeping (updated) as a fallback.
    const defaultTheme = r.kind === 'theme' && /^twenty/.test(r.slug || '');
    if (inactive && (vulnerable || r.closed || (behind && !defaultTheme))) {
      push('remove', r, { steps: removeSteps(r) });
    } else if (r.closed && r.status !== 'parent' && r.kind !== 'theme') {
      push('remove', r, { steps: removeSteps(r) });
    } else if (vulnerable && anyUnfixed) {
      push('nofix', r, { steps: removeSteps(r) });
    } else if (vulnerable) {
      push('fix', r, { steps: updateSteps(r) });
    } else if (r.latest && compareVersions(r.version, r.latest) < 0) {
      push('update', r, { steps: updateSteps(r) });
    } else {
      push('ok', r);
    }
  }
  return out;
}

export function hostEmail(php) {
  const fixes = php.vulns.map((v) => v.fixedIn).filter(Boolean).sort(compareVersions);
  const target = fixes.length ? fixes[fixes.length - 1] : null;
  const cves = [...new Set(php.vulns.flatMap((v) => v.cves))].slice(0, 8);
  const lines = [
    'Hello,',
    '',
    `Our WordPress site's Site Health page reports PHP ${php.version}.`,
  ];
  if (php.endOfLife) {
    lines.push(`PHP ${php.branch} no longer receives security fixes. Could you move our site to a supported PHP version, or tell us how to choose one in our control panel?`);
  }
  if (php.vulns.length) {
    lines.push(
      `Public vulnerability databases list security problems affecting this version${cves.length ? ' (for example ' + cves.join(', ') + ')' : ''}.` +
        (target ? ` They are fixed in PHP ${target} and later.` : '')
    );
    lines.push('Could you confirm whether your PHP build already includes these fixes, and if not, when it will be updated?');
  }
  lines.push('', 'Thank you.');
  return lines.join('\n');
}
