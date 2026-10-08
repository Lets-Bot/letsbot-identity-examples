import express from 'express';
import { createIdentityToken } from './identity.js';
// Using the LetsBot TypeScript SDK instead? Same result:
//   import { createIdentityToken } from '@letsbot/sdk';
//   createIdentityToken({ userId, secret, expiresIn: '24h', name, email, phone })

// Placeholder authentication — replace with your own session / auth middleware.
const DEMO_SESSIONS = {
  'demo-session': { id: 'user-42', name: 'Sara', email: 'sara@example.com', phone: '+966501234567' },
};
function requireUser(req, res, next) {
  const bearer = (req.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
  req.user = DEMO_SESSIONS[bearer];
  if (!req.user) return res.status(401).json({ error: 'unauthenticated' });
  next();
}

export function createApp({ secret = process.env.LETSBOT_IDENTITY_SECRET } = {}) {
  const app = express();

  app.get('/api/letsbot/identity-token', requireUser, (req, res) => {
    const token = createIdentityToken({
      userId: req.user.id,
      secret,
      ttlSeconds: 24 * 60 * 60,
      name: req.user.name,
      email: req.user.email,
      phone: req.user.phone,
    });
    const { exp } = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    res.set('Cache-Control', 'no-store').json({ token, expires_at: exp });
  });

  return app;
}
