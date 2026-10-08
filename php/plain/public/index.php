<?php

// php -S localhost:8000 -t plain/public
declare(strict_types=1);

require_once __DIR__.'/../endpoint.php';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($_SERVER['REQUEST_METHOD'] !== 'GET' || $path !== '/api/letsbot/identity-token') {
    http_response_code(404);
    exit;
}

$secret = getenv('LETSBOT_IDENTITY_SECRET') ?: '';
if ($secret === '') {
    http_response_code(500);
    exit('Set LETSBOT_IDENTITY_SECRET');
}

[$status, $headers, $body] = handle_identity_token_request($_SERVER, $secret);
http_response_code($status);
foreach ($headers as $name => $value) {
    header("$name: $value");
}
echo $body;
