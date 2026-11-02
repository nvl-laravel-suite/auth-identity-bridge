<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Closure;
use IdentityPlatform\Laravel\Auth\SessionManager;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireSession
{
    public function __construct(private SessionManager $sessions) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->sessions->current($request)) {
            return $request->expectsJson() ? response()->json(['error' => 'sign_in_required'], 401) : redirect('/');
        }

        return $next($request);
    }
}
