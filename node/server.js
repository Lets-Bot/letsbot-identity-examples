import { createApp } from './app.js';

if (!process.env.LETSBOT_IDENTITY_SECRET) {
  console.error('Set LETSBOT_IDENTITY_SECRET (LetsBot panel → In-App Chat → your app → Identity Secret).');
  process.exit(1);
}
const port = Number(process.env.PORT ?? 3000);
createApp().listen(port, () => console.log(`Listening on http://localhost:${port}`));
