<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Closure;
use IdentityPlatform\Laravel\Auth\SessionManager;
use Illuminate\Http\Request;

class RequireSession
{
    public function __construct(private SessionManager $sessions) {}

    public function handle(Request $request, Closure $next)
    {
        if (! $this->sessions->current($request)) {
            return $request->expectsJson() ? response()->json(['error' => 'sign_in_required'], 401) : redirect('/');
        }

        return $next($request);
    }
}
