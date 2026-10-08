import { createHmac } from 'node:crypto';

const MAX_TTL_SECONDS = 7 * 24 * 60 * 60;

/**
 * LetsBot In-App Chat identity token: JWT, HS256, signed with the app's Identity Secret.
 * Claims: sub, iat, exp (+ optional name, email, phone).
 */
export function createIdentityToken({ userId, secret, ttlSeconds = 24 * 60 * 60, name, email, phone, now }) {
  if (typeof secret !== 'string' || secret === '') throw new TypeError('Identity Secret is missing');
  const sub = String(userId ?? '').trim();
  if (sub === '' || [...sub].length > 191) throw new RangeError('userId must be 1-191 characters');
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) {
    throw new RangeError('ttlSeconds must be between 1 and 604800 (7 days)');
  }

  const iat = now ?? Math.floor(Date.now() / 1000);
  const claims = { sub, iat, exp: iat + ttlSeconds };
  if (name) claims.name = name;
  if (email) claims.email = email;
  if (phone) claims.phone = phone;

  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(claims)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}
