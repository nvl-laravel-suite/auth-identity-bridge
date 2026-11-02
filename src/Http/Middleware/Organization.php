<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Illuminate\Http\Request;

class Organization extends RequireAuthority
{
    public function handle(Request $request, \Closure $next, string $value = '', string $unused = '')
    {
        return parent::handle($request, $next, 'organization', $value);
    }
}
