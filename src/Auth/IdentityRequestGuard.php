<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use Illuminate\Auth\RequestGuard;
use Illuminate\Http\Request;

/** Cached authentication belongs to one request, including in persistent workers. */
final class IdentityRequestGuard extends RequestGuard
{
    public function setRequest(Request $request)
    {
        $this->forgetUser();

        return parent::setRequest($request);
    }
}
