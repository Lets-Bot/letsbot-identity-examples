import assert from 'node:assert/strict';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { test } from 'node:test';
import { createApp } from '../app.js';
import { createIdentityToken } from '../identity.js';

const SECRET = 'letsbot-test-identity-secret-0123456789';

function verifyHs256(token, secret) {
  const [h, p, s] = token.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  assert.equal(header.alg, 'HS256');
  const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  const given = Buffer.from(s, 'base64url');
  assert.ok(given.length === expected.length && timingSafeEqual(given, expected), 'signature must verify');
  return JSON.parse(Buffer.from(p, 'base64url'));
}

test('token verifies with HS256 and has sub/iat/exp', () => {
  const claims = verifyHs256(createIdentityToken({ userId: 42, secret: SECRET, now: 1791446400 }), SECRET);
  assert.deepEqual(claims, { sub: '42', iat: 1791446400, exp: 1791446400 + 86400 });
  assert.throws(() => verifyHs256(createIdentityToken({ userId: 42, secret: 'other' }), SECRET));
});

test('rejects bad input', () => {
  assert.throws(() => createIdentityToken({ userId: 'u', secret: '' }), TypeError);
  assert.throws(() => createIdentityToken({ userId: 'x'.repeat(192), secret: SECRET }), RangeError);
  assert.throws(() => createIdentityToken({ userId: 'u', secret: SECRET, ttlSeconds: 604801 }), RangeError);
});

test('GET /api/letsbot/identity-token', async (t) => {
  const server = createApp({ secret: SECRET }).listen(0);
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/api/letsbot/identity-token`;

  assert.equal((await fetch(url)).status, 401);

  const res = await fetch(url, { headers: { Authorization: 'Bearer demo-session' } });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const body = await res.json();
  const claims = verifyHs256(body.token, SECRET);
  assert.equal(claims.sub, 'user-42');
  assert.equal(claims.email, 'sara@example.com');
  assert.equal(claims.exp - claims.iat, 86400);
  assert.equal(body.expires_at, claims.exp);
});
