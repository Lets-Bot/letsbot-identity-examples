<?php

declare(strict_types=1);

/**
 * LetsBot In-App Chat identity token without any library: JWT, HS256, signed with the app's
 * Identity Secret. Claims: sub, iat, exp (+ optional name, email, phone).
 *
 * @param array{name?: string, email?: string, phone?: string} $extra
 */
function letsbot_identity_token(string|int $userId, string $secret, int $ttlSeconds = 86400, array $extra = [], ?int $now = null): string
{
    if ($secret === '') {
        throw new InvalidArgumentException('Identity Secret is missing');
    }
    $sub = trim((string) $userId);
    if ($sub === '' || mb_strlen($sub) > 191) {
        throw new InvalidArgumentException('userId must be 1-191 characters');
    }
    if ($ttlSeconds < 1 || $ttlSeconds > 7 * 86400) {
        throw new InvalidArgumentException('ttlSeconds must be between 1 and 604800 (7 days)');
    }

    $iat = $now ?? time();
    $claims = ['sub' => $sub, 'iat' => $iat, 'exp' => $iat + $ttlSeconds];
    foreach (['name', 'email', 'phone'] as $key) {
        if (isset($extra[$key]) && $extra[$key] !== '') {
            $claims[$key] = (string) $extra[$key];
        }
    }

    $b64 = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    $json = static fn (array $value): string => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $input = $b64($json(['alg' => 'HS256', 'typ' => 'JWT'])).'.'.$b64($json($claims));

    return $input.'.'.$b64(hash_hmac('sha256', $input, $secret, true));
}
