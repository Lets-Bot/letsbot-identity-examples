<?php

// routes/api.php — Laravel 10+ with firebase/php-jwt.
// .env:            LETSBOT_IDENTITY_SECRET=...
// config/services.php:  'letsbot' => ['identity_secret' => env('LETSBOT_IDENTITY_SECRET')],

use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->get('/letsbot/identity-token', function (Request $request) {
    $user = $request->user();
    $now = time();
    $exp = $now + 24 * 60 * 60; // 24 h recommended, 7 days max

    $token = JWT::encode(array_filter([
        'sub' => (string) $user->getKey(),   // stable id, ≤ 191 characters
        'iat' => $now,
        'exp' => $exp,
        'name' => $user->name,
        'email' => $user->email,
        'phone' => $user->phone ?? null,
    ], fn ($value) => $value !== null && $value !== ''), config('services.letsbot.identity_secret'), 'HS256');

    return response()
        ->json(['token' => $token, 'expires_at' => $exp])
        ->header('Cache-Control', 'no-store');
});
