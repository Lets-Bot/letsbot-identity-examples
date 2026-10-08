<?php

declare(strict_types=1);

require_once __DIR__.'/identity.php';

/**
 * Placeholder authentication — replace with your own session lookup.
 *
 * @return array{id: string, name: string, email: string, phone: string}|null
 */
function current_user(array $server): ?array
{
    $sessions = [
        'demo-session' => ['id' => 'user-42', 'name' => 'Sara', 'email' => 'sara@example.com', 'phone' => '+966501234567'],
    ];
    $bearer = preg_replace('/^Bearer\s+/i', '', $server['HTTP_AUTHORIZATION'] ?? '');

    return $sessions[$bearer] ?? null;
}

/**
 * GET /api/letsbot/identity-token
 *
 * @return array{0: int, 1: array<string, string>, 2: string} status, headers, body
 */
function handle_identity_token_request(array $server, string $secret): array
{
    $headers = ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'];
    $user = current_user($server);
    if ($user === null) {
        return [401, $headers, '{"error":"unauthenticated"}'];
    }

    $ttl = 86400; // 24 h recommended, 7 days max
    $now = time();
    $token = letsbot_identity_token($user['id'], $secret, $ttl, $user, $now);

    return [200, $headers, json_encode(['token' => $token, 'expires_at' => $now + $ttl], JSON_THROW_ON_ERROR)];
}
