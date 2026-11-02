<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Closure;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Http\Request;

class BrowserSafety
{
    public function __construct(private IdentityConfig $config) {}

    public function handle(Request $request, Closure $next)
    {
        try {
            if (! in_array($request->method(), ['GET', 'HEAD', 'OPTIONS'], true) && $request->header('Origin') !== $this->config->appOrigin()) {
                throw new IdentityException('origin_refused', 403);
            }
            $cookie = preg_quote((string) config('session.cookie'), '/');
            if (preg_match_all('/(?:^|;\s*)'.$cookie.'=/', (string) $request->server('HTTP_COOKIE')) > 1) {
                throw new IdentityException('duplicate_session_cookie', 400);
            }
            $response = $next($request);
        } catch (IdentityException $e) {
            $response = response()->json(['error' => $e->errorCode], $e->status);
            if ($e->retryAfter !== null) {
                $response->headers->set('Retry-After', (string) $e->retryAfter);
            }
        }
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Referrer-Policy', 'strict-origin');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return $response;
    }
}
