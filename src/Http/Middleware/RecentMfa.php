<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RecentMfa extends RequireAuthority
{
    /** @param \Closure(Request): Response $next */
    public function handle(Request $request, \Closure $next, string $value = '', string $unused = ''): Response
    {
        return parent::handle($request, $next, 'mfa');
    }
}
