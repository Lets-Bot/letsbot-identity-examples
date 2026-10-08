<?php

declare(strict_types=1);

use Firebase\JWT\JWT;

/**
 * Same token with firebase/php-jwt (`composer require firebase/php-jwt`).
 *
 * @param array{name?: string, email?: string, phone?: string} $extra
 */
function letsbot_identity_token_firebase(string|int $userId, string $secret, int $ttlSeconds = 86400, array $extra = [], ?int $now = null): string
{
    if ($secret === '') {
        throw new InvalidArgumentException('Identity Secret is missing');
    }
    $sub = trim((string) $userId);
    if ($sub === '' || mb_strlen($sub) > 191 || $ttlSeconds < 1 || $ttlSeconds > 7 * 86400) {
        throw new InvalidArgumentException('userId must be 1-191 characters and ttlSeconds at most 7 days');
    }

    $iat = $now ?? time();
    $claims = ['sub' => $sub, 'iat' => $iat, 'exp' => $iat + $ttlSeconds];
    foreach (['name', 'email', 'phone'] as $key) {
        if (! empty($extra[$key])) {
            $claims[$key] = (string) $extra[$key];
        }
    }

    return JWT::encode($claims, $secret, 'HS256');
}
