# PHP

| File | What |
|---|---|
| `plain/identity.php` | `letsbot_identity_token()` — no dependencies (`hash_hmac`) |
| `plain/endpoint.php`, `plain/public/index.php` | `GET /api/letsbot/identity-token` in plain PHP (placeholder auth — replace `current_user()`) |
| `firebase/identity.php` | Same token with [`firebase/php-jwt`](https://github.com/firebase/php-jwt) |
| `laravel/routes-api.php` | Laravel route behind `auth:sanctum` using `firebase/php-jwt` |

```php
$token = letsbot_identity_token($user->id, getenv('LETSBOT_IDENTITY_SECRET'), 86400, [
    'name' => $user->name, 'email' => $user->email,
]);
```

## Run

```bash
composer install                 # only needed for the firebase/php-jwt checks
php tests/run.php
LETSBOT_IDENTITY_SECRET=... php -S localhost:8000 -t plain/public
curl -H 'Authorization: Bearer demo-session' http://localhost:8000/api/letsbot/identity-token
```

The Laravel snippet is not executed by the tests; it uses the same `JWT::encode(..., 'HS256')` call that
`tests/run.php` verifies.
