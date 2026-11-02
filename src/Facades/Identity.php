<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Facades;

use IdentityPlatform\Laravel\Auth\BrowserLifecycle;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;

/** @mixin IdentityAccess
 * @api
 */
class Identity extends Facade
{
    public static function consumer(string $name, ?Request $request = null): ConsumerGraph
    {
        return app(\IdentityPlatform\Laravel\Identity::class)->consumer($name, $request);
    }

    public static function browser(): BrowserLifecycle
    {
        return app(\IdentityPlatform\Laravel\Identity::class)->browser();
    }

    protected static function getFacadeAccessor(): string
    {
        return IdentityAccess::class;
    }
}
