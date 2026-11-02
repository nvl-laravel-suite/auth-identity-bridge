<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Http\Request;

/** Shared POST + exact Origin + native CSRF admission for public browser commands. */
final class BrowserCommand
{
    public function __construct(private IdentityConfig $config) {}

    public function assert(Request $request): void
    {
        if ($request->method() !== 'POST' || $request->header('Origin') !== $this->config->appOrigin()) {
            throw new IdentityException('origin_refused', 403);
        }
        $token = $request->input('_token', $request->header('X-CSRF-TOKEN'));
        if (! $request->hasSession() || ! is_string($token) || ! is_string($request->session()->token()) || ! hash_equals($request->session()->token(), $token)) {
            throw new IdentityException('csrf_refused', 419);
        }
    }
}
