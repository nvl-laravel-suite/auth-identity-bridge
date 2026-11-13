<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Closure;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Services\ResourceVerifier;
use Illuminate\Http\Request;
use Stringable;
use Symfony\Component\HttpFoundation\Response;

class ApiCredential
{
    public function __construct(private ResourceVerifier $verifier) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next, string $kind, string $organizationParameter = ''): Response
    {
        try {
            $authorization = $request->header('Authorization', '');
            if (! preg_match('/^Bearer ([^\s,]{1,8192})$/D', $authorization, $matches)) {
                throw new IdentityException('credential_required', 401);
            }
            $organization = $organizationParameter !== '' ? $request->route($organizationParameter) : null;
            if (is_object($organization) && method_exists($organization, 'getKey')) {
                $key = $organization->getKey();
                $organization = is_scalar($key) || $key === null || $key instanceof Stringable ? (string) $key : null;
            }
            if ($organizationParameter !== '' && (! is_string($organization) || $organization === '')) {
                throw new IdentityException('organization_required', 403);
            }
            $request->attributes->set('identity.principal', $this->verifier->verify($kind, $matches[1], $organization));
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
