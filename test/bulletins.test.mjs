import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const bulletins = JSON.parse(readFileSync(new URL('../site/bulletins.json', import.meta.url), 'utf8'));
const NEED = ['id', 'date', 'severity', 'title', 'summary', 'affects', 'check', 'fix', 'technical', 'sources'];

test('bulletins.json entries are complete and well-formed', () => {
  const ids = new Set();
  for (const b of bulletins) {
    for (const k of NEED) assert.ok(k in b, `${b.id || '?'} missing ${k}`);
    assert.ok(!ids.has(b.id), `duplicate id ${b.id}`);
    ids.add(b.id);
    assert.match(b.id, /^[a-z0-9-]+$/, `${b.id}: id must be lowercase-dashed (used as a link anchor)`);
    assert.ok(['critical', 'high', 'medium', 'low'].includes(b.severity), `${b.id}: bad severity`);
    assert.match(b.date, /^\d{4}-\d{2}-\d{2}$/, `${b.id}: bad date`);
    assert.ok(Array.isArray(b.check) && b.check.length, `${b.id}: needs check steps`);
    assert.ok(Array.isArray(b.fix) && b.fix.length, `${b.id}: needs fix steps`);
    for (const s of b.sources) assert.match(s, /^https:\/\//, `${b.id}: source must be https`);
    for (const a of b.affects) assert.ok(['plugin', 'theme', 'core', 'php'].includes(a.kind), `${b.id}: bad affects.kind`);
  }
});
