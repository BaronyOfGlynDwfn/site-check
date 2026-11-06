import { parseSiteHealth, checkSite, classify, GROUPS, compareVersions, bulletinApplies } from './lib.js';

// Every string from the paste or the lookup services goes through textContent,
// never innerHTML.
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) n.append(k);
  return n;
}

function safeLink(url, text) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error();
    return el('a', { href: u.href, rel: 'noopener noreferrer', target: '_blank', text: text || u.href });
  } catch {
    return document.createTextNode(text || '');
  }
}

const cache = new Map();
async function fetchJson(url) {
  if (cache.has(url)) return cache.get(url);
  const p = (async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      const r = await fetch(url, { headers: { Accept: 'application/json' } });
      if (r.status === 429 || r.status >= 500) {
        await new Promise((res) => setTimeout(res, 1500 * (attempt + 1)));
        continue;
      }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }
    throw new Error('service busy');
  })();
  cache.set(url, p);
  p.catch(() => cache.delete(url));
  return p;
}

const KIND = { core: 'WordPress', php: 'PHP', plugin: 'Plugin', theme: 'Theme', 'mu-plugin': 'Must-use plugin' };
const STATUS = { active: 'active', inactive: 'inactive', parent: 'parent theme' };

let bulletins = [];

function bulletinFor(item) {
  return bulletins.filter((b) => (b.affects || []).some((a) => bulletinApplies(a, item)));
}

function vulnList(vulns) {
  const seen = new Set();
  const lis = [];
  for (const v of vulns) {
    const key = v.title + v.cves.join();
    if (seen.has(key)) continue;
    seen.add(key);
    lis.push(
      el('li', {},
        v.link ? safeLink(v.link, v.title) : v.title,
        v.severity ? el('span', { class: `badge sev-${v.severity}`, text: v.severity }) : null,
        v.exploited ? el('span', { class: 'badge hot', text: 'being attacked' }) : null,
        v.cves.length ? el('span', { class: 'muted', text: ' ' + v.cves.join(', ') }) : null,
        v.fixedIn ? el('span', { class: 'muted', text: ` · fixed in ${v.fixedIn}` }) : null
      )
    );
  }
  return el('ul', { class: 'vulns' }, lis);
}

function card(entry) {
  const r = entry.item;
  const bits = [KIND[r.kind] || r.kind];
  if (r.status && STATUS[r.status]) bits.push(STATUS[r.status]);
  if (r.version) bits.push(`installed ${r.version}`);
  if (r.latest && r.version && compareVersions(r.version, r.latest) < 0) bits.push(`latest ${r.latest}`);
  if (r.kind === 'php' && r.distroBuild) bits.push(`reported as ${r.raw}: your host's Linux distribution may patch PHP without changing the number`);
  if (r.kind === 'php' && r.endOfLife) bits.push(`PHP ${r.branch} is past end of life`);

  const exploited = (r.vulns || []).some((v) => v.exploited);
  const c = el('article', { class: 'card' },
    el('h4', {}, r.name, exploited ? el('span', { class: 'badge hot', text: 'being attacked' }) : null),
    el('p', { class: 'meta', text: bits.join(' · ') })
  );
  if (entry.note) c.append(el('p', { class: 'muted', text: entry.note }));
  if (r.checked && r.slug && (r.kind === 'plugin' || r.kind === 'theme')) {
    c.append(el('p', { class: 'meta' }, 'Matched to ',
      safeLink(`https://wordpress.org/${r.kind}s/${encodeURIComponent(r.slug)}/`, `wordpress.org/${r.kind}s/${r.slug}`),
      r.matchedBy === 'name+version' ? ' (by name and version; check this is the same one)' : ''));
  }
  if (entry.steps?.length) c.append(el('ol', {}, entry.steps.map((s) => el('li', { text: s }))));
  if (entry.email) {
    const pre = el('pre', { class: 'email', text: entry.email });
    const btn = el('button', { type: 'button', class: 'quiet copy', text: 'Copy message' });
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(entry.email);
        btn.textContent = 'Copied';
      } catch {
        btn.textContent = 'Select the text and copy it';
      }
    });
    c.append(pre, btn);
  }
  const bs = bulletinFor(r);
  if (bs.length) {
    c.append(el('p', { class: 'muted' }, 'See bulletin: ', ...bs.map((b, i) =>
      el('span', {}, i ? ', ' : '', el('a', { href: `#${b.id}`, text: b.title }))
    )));
  }
  if (r.vulns?.length) {
    c.append(el('details', {}, el('summary', { text: `Technical details (${r.vulns.length})` }), vulnList(r.vulns)));
  }
  return c;
}

// Low-urgency groups: one card, one row per item, one set of steps.
function compactCard(groupId, list) {
  const rows = list.map(({ item: r, note }) => {
    const bits = [KIND[r.kind] || r.kind];
    if (r.status && STATUS[r.status]) bits.push(STATUS[r.status]);
    if (r.version) bits.push(r.latest && groupId === 'update' ? `${r.version} → ${r.latest}` : r.version);
    return el('li', {}, el('strong', { text: r.name }), el('span', { class: 'muted', text: ' · ' + bits.join(' · ') }),
      groupId === 'unchecked' && note && !note.startsWith('Not listed') ? el('div', { class: 'muted', text: note }) : null);
  });
  const steps = groupId === 'update'
    ? [
        'Make a backup first.',
        'Go to Dashboard → Updates. Everything in this list appears there with a checkbox.',
        'Tick them and click "Update Plugins" / "Update Themes". WordPress updates itself from the same page.',
        'Open your home page and one inner page afterwards to check they still load.',
      ]
    : [
        'These came from somewhere other than wordpress.org (your own code, a paid plugin, or your host), or the name didn\'t match a listing closely enough to be sure.',
        'For each one, ask whoever made or installed it whether it is still maintained, and update it from their site.',
        'If nobody knows what it is or why it is there, deactivate it, check the site, and delete it.',
      ];
  return el('article', { class: 'card' },
    el('ul', { class: 'rows' }, rows),
    el('ol', {}, steps.map((t) => el('li', { text: t })))
  );
}

function render(entries, results) {
  const out = document.getElementById('results');
  out.replaceChildren();
  const byGroup = Object.fromEntries(GROUPS.map((g) => [g.id, []]));
  for (const e of entries) byGroup[e.group].push(e);

  const chips = GROUPS.filter((g) => byGroup[g.id].length).map((g) =>
    el('a', { class: `chip g-${g.id}`, href: `#grp-${g.id}`, text: `${g.title}: ${byGroup[g.id].length}` })
  );
  out.append(el('div', { class: 'summary' }, chips));

  const urgent = byGroup.fix.length + byGroup.nofix.length;
  out.append(el('p', {
    text: urgent
      ? `Start with the ${urgent} item${urgent > 1 ? 's' : ''} at the top. Each one has the exact steps.`
      : 'No known security problems found in what could be checked. Look through the rest when you have time.',
  }));

  for (const g of GROUPS) {
    const list = byGroup[g.id];
    if (!list.length) continue;
    const sec = el('section', { class: `group g-${g.id}`, id: `grp-${g.id}` },
      el('header', {}, el('h3', { text: g.title }), el('p', { text: g.blurb }))
    );
    if (g.id === 'update' || g.id === 'unchecked') {
      sec.append(compactCard(g.id, list));
    } else if (g.id === 'ok') {
      sec.append(el('ul', { class: 'oklist' }, list.map((e) =>
        el('li', { text: `${e.item.name}${e.item.version ? ' ' + e.item.version : ''}` })
      )));
    } else {
      for (const e of list) sec.append(card(e));
    }
    out.append(sec);
  }

  if (results.userRegistration) {
    out.append(el('section', { class: 'group g-unchecked' },
      el('header', {}, el('h3', { text: 'Also worth a look' })),
      el('article', { class: 'card' },
        el('h4', { text: 'Anyone can register an account' }),
        el('p', { text: 'Settings → General → "Anyone can register" is on. Several problems above only need a low-level account to exploit. Turn it off unless your site needs public sign-ups (a forum, for example), and make sure "New User Default Role" is Subscriber.' })
      )
    ));
  }
}

function renderBulletins() {
  const box = document.getElementById('bulletin-list');
  box.replaceChildren();
  const sorted = [...bulletins].sort((a, b) => b.date.localeCompare(a.date));
  for (const b of sorted) {
    const art = el('article', { class: `bulletin sev-${b.severity}`, id: b.id },
      el('h3', { text: b.title }),
      el('p', { class: 'meta' }, `${b.date} · `, el('span', { class: `badge sev-${b.severity}`, text: b.severity })),
      el('p', { text: b.summary }),
      el('h4', { text: 'How to check' }), el('ol', {}, b.check.map((s) => el('li', { text: s }))),
      el('h4', { text: 'How to fix' }), el('ol', {}, b.fix.map((s) => el('li', { text: s }))),
      b.help ? el('h4', { text: 'If you get stuck' }) : null,
      b.help ? el('p', { text: b.help }) : null,
      el('details', {},
        el('summary', { text: 'Technical details' }),
        el('p', { text: b.technical }),
        el('ul', {}, (b.sources || []).map((s) => el('li', {}, safeLink(s))))
      )
    );
    box.append(art);
  }
  if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
}

async function onCheck(ev) {
  ev.preventDefault();
  const err = document.getElementById('error');
  const prog = document.getElementById('progress');
  const go = document.getElementById('go');
  err.hidden = true;
  document.getElementById('results').replaceChildren();
  let info;
  try {
    info = parseSiteHealth(document.getElementById('paste').value);
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
    return;
  }
  go.disabled = true;
  try {
    const results = await checkSite(info, fetchJson, (n, total, label) => {
      prog.textContent = `Checking ${n} of ${total}: ${label}`;
    });
    prog.textContent = `Checked ${info.items.length} plugins and themes.`;
    render(classify(results), results);
    document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) {
    err.textContent = 'The lookup services could not be reached (' + e.message + '). Check your connection and try again.';
    err.hidden = false;
    prog.textContent = '';
  } finally {
    go.disabled = false;
  }
}

document.getElementById('check-form').addEventListener('submit', onCheck);
document.getElementById('clear').addEventListener('click', () => {
  document.getElementById('paste').value = '';
  document.getElementById('results').replaceChildren();
  document.getElementById('progress').textContent = '';
  document.getElementById('error').hidden = true;
});

fetch('bulletins.json')
  .then((r) => r.json())
  .then((b) => { bulletins = b; renderBulletins(); })
  .catch(() => {
    document.getElementById('bulletin-list').textContent = 'Bulletins could not be loaded.';
  });
