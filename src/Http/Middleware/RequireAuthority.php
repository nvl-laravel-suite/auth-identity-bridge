<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Closure;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Http\Request;
use Stringable;
use Symfony\Component\HttpFoundation\Response;

class RequireAuthority
{
    public function __construct(private SessionManager $sessions) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next, string $kind, string $value = ''): Response
    {
        $principal = $request->attributes->get('identity.principal');
        $freshRequired = ! in_array($request->method(), ['GET', 'HEAD'], true) || $kind === 'mfa';
        $cachedBrowser = $principal instanceof Principal && ($principal->decision['contract'] ?? null) === 'platform-authorization-snapshot.v1';
        if (! $principal instanceof Principal || ($cachedBrowser && $freshRequired && ! $request->attributes->get('identity.principal.fresh', false))) {
            $write = ! in_array($request->method(), ['GET', 'HEAD'], true);
            if ($write) {
                $row = $this->sessions->current($request);
                $version = $request->input('context_version', $request->header('X-Identity-Context-Version'));
                if (! $row || ! is_scalar($version) || ! ctype_digit((string) $version) || (int) $version !== $row->context_version) {
                    throw new IdentityException('context_changed', 409);
                }
            }
            $principal = $this->sessions->principal($request, $freshRequired);
            $request->attributes->set('identity.principal', $principal);
            $request->attributes->set('identity.principal.fresh', $freshRequired);
        }
        $expectedOrganization = $kind === 'organization' ? $request->route($value) : null;
        if (is_object($expectedOrganization) && method_exists($expectedOrganization, 'getKey')) {
            $key = $expectedOrganization->getKey();
            $expectedOrganization = is_scalar($key) || $key === null || $key instanceof Stringable ? (string) $key : null;
        }
        $allowed = match ($kind) {
            'permission' => $principal->hasPermission($value),
            'role' => $principal->hasRole($value),
            'mfa' => $principal->recentMfa(),
            'organization' => is_string($expectedOrganization) && $expectedOrganization !== '' && $principal->organizationId() === $expectedOrganization,
            default => false,
        };
        if (! $allowed) {
            throw new IdentityException('access_denied', 403);
        }

        return $next($request);
    }
}
