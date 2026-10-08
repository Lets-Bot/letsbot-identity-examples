# Node.js (Express)

`identity.js` mints the token with `node:crypto` only; `app.js` exposes `GET /api/letsbot/identity-token` behind a
placeholder auth check (replace `requireUser` with your own).

If you already use the LetsBot TypeScript SDK, `createIdentityToken` from `@letsbot/sdk` does the same thing:

```js
import { createIdentityToken } from '@letsbot/sdk';
const token = createIdentityToken({ userId: user.id, secret: process.env.LETSBOT_IDENTITY_SECRET, expiresIn: '24h' });
```

## Run

```bash
npm install
npm test                                   # node --test
LETSBOT_IDENTITY_SECRET=... npm start      # http://localhost:3000
curl -H 'Authorization: Bearer demo-session' http://localhost:3000/api/letsbot/identity-token
```
