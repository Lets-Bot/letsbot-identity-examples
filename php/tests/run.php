<?php

// php tests/run.php — no test framework needed.
declare(strict_types=1);

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require_once __DIR__.'/../plain/identity.php';
require_once __DIR__.'/../plain/endpoint.php';

$hasFirebase = is_file(__DIR__.'/../vendor/autoload.php');
if ($hasFirebase) {
    require_once __DIR__.'/../vendor/autoload.php';
    require_once __DIR__.'/../firebase/identity.php';
}

const SECRET = 'letsbot-test-identity-secret-0123456789';
$passed = 0;

function check(bool $condition, string $message): void
{
    global $passed;
    if (! $condition) {
        fwrite(STDERR, "FAIL: $message\n");
        exit(1);
    }
    $passed++;
}

/** Independent HS256 verification; returns the claims or null. */
function verify_hs256(string $token, string $secret): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return null;
    }
    [$h, $p, $s] = $parts;
    $decode = static fn (string $v): string => base64_decode(strtr($v, '-_', '+/'), true) ?: '';
    $header = json_decode($decode($h), true);
    if (($header['alg'] ?? null) !== 'HS256') {
        return null;
    }
    $expected = hash_hmac('sha256', "$h.$p", $secret, true);

    return hash_equals($expected, $decode($s)) ? json_decode($decode($p), true) : null;
}

// Plain PHP token
$token = letsbot_identity_token(42, SECRET, 86400, ['name' => 'Sara', 'phone' => ''], 1791446400);
check(verify_hs256($token, SECRET) === ['sub' => '42', 'iat' => 1791446400, 'exp' => 1791532800, 'name' => 'Sara'], 'plain token verifies with sub/iat/exp');
check(verify_hs256($token, SECRET.'x') === null, 'wrong secret fails');

foreach ([['', 'u', 60], [SECRET, '', 60], [SECRET, str_repeat('x', 192), 60], [SECRET, 'u', 604801]] as [$secret, $user, $ttl]) {
    try {
        letsbot_identity_token($user, $secret, $ttl);
        check(false, 'invalid input must throw');
    } catch (InvalidArgumentException) {
        check(true, 'invalid input throws');
    }
}

// Endpoint
[$status] = handle_identity_token_request([], SECRET);
check($status === 401, 'endpoint without session is 401');
[$status, $headers, $body] = handle_identity_token_request(['HTTP_AUTHORIZATION' => 'Bearer demo-session'], SECRET);
check($status === 200 && $headers['Cache-Control'] === 'no-store', 'endpoint with session is 200 no-store');
$json = json_decode($body, true);
$claims = verify_hs256($json['token'], SECRET);
check($claims !== null && $claims['sub'] === 'user-42' && $claims['exp'] - $claims['iat'] === 86400, 'endpoint token verifies');
check($json['expires_at'] === $claims['exp'], 'expires_at matches exp');

// firebase/php-jwt: decode the plain token, and verify the firebase token independently
if ($hasFirebase) {
    $decoded = (array) JWT::decode(letsbot_identity_token('user-42', SECRET), new Key(SECRET, 'HS256'));
    check($decoded['sub'] === 'user-42' && isset($decoded['iat'], $decoded['exp']), 'firebase/php-jwt decodes the plain token');

    $firebaseToken = letsbot_identity_token_firebase('user-42', SECRET, 3600, ['email' => 'sara@example.com'], 1791446400);
    check(verify_hs256($firebaseToken, SECRET) == ['sub' => 'user-42', 'iat' => 1791446400, 'exp' => 1791450000, 'email' => 'sara@example.com'], 'firebase token verifies with sub/iat/exp');
} else {
    echo "SKIP firebase/php-jwt checks (run composer install)\n";
}

echo "OK $passed checks\n";
