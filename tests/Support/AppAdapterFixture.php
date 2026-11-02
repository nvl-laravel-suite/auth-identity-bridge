<?php

declare(strict_types=1);

namespace ConsumerHostFixtures;

use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Repositories\LoginRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Factory;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\DatabaseManager;

final class AppHelper
{
    public function __construct(public IdentityConfig $config, public LoginRepository $logins, public IdentityHttp $http, public Factory $cache, public Dispatcher $events, public DatabaseManager $database, public Container $container) {}
}

interface HelperContract {}

final class BoundHelper implements HelperContract
{
    public function __construct(public AppHelper $helper) {}
}

final class AppMapper implements NativeUserMapper
{
    public function __construct(public AppHelper $helper, public HelperContract $bound) {}

    public function synchronize(Authenticatable $user, IdentityUser $projection): void {}
}
