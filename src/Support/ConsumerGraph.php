<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Closure;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry;
use IdentityPlatform\Laravel\Auth\AuthStatePresenter;
use IdentityPlatform\Laravel\Auth\BrowserLifecycle;
use IdentityPlatform\Laravel\Auth\LocalDestinationResolver;
use IdentityPlatform\Laravel\Auth\PostContextDestinationResolver;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\AuthorizationClient;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner;
use IdentityPlatform\Laravel\Callbacks\CallbackReceiver;
use IdentityPlatform\Laravel\Callbacks\CallbackRepository;
use IdentityPlatform\Laravel\Callbacks\IdentityEventVerifier;
use IdentityPlatform\Laravel\Callbacks\LogoutTokenVerifier;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Delegation\DelegatedActionRepository;
use IdentityPlatform\Laravel\Delegation\DelegatedActionRunner;
use IdentityPlatform\Laravel\Delegation\DelegationExecutionGuard;
use IdentityPlatform\Laravel\Delegation\DelegationManager;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Controllers\ApplicationContextController;
use IdentityPlatform\Laravel\Http\Controllers\BrowserController;
use IdentityPlatform\Laravel\Http\Controllers\CallbackController;
use IdentityPlatform\Laravel\Http\Middleware\ApiCredential;
use IdentityPlatform\Laravel\Http\Middleware\BrowserSafety;
use IdentityPlatform\Laravel\Http\Middleware\DelegationBoundary;
use IdentityPlatform\Laravel\Http\Middleware\RequireAuthority;
use IdentityPlatform\Laravel\Http\Middleware\RequireSession;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Oidc\IdTokenVerifier;
use IdentityPlatform\Laravel\Oidc\OidcClient;
use IdentityPlatform\Laravel\Oidc\TrustedProviderMetadata;
use IdentityPlatform\Laravel\Profiles\LocalProfileManager;
use IdentityPlatform\Laravel\Profiles\LocalProfileRepository;
use IdentityPlatform\Laravel\Repositories\LoginRepository;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Services\ResourceVerifier;
use IdentityPlatform\Laravel\Sessions\LocalSessionDirectory;
use IdentityPlatform\Laravel\Sync\UserImportBootstrap;
use IdentityPlatform\Laravel\Sync\UserImportClient;
use IdentityPlatform\Laravel\Sync\UserImportMapping;
use IdentityPlatform\Laravel\Sync\UserSnapshotClient;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use IdentityPlatform\Laravel\Sync\UserSyncWorkRepository;
use IdentityPlatform\Laravel\Users\EloquentIdentityUserResolver;
use IdentityPlatform\Laravel\Users\EloquentNativeUserFactory;
use IdentityPlatform\Laravel\Users\EloquentNativeUserMapper;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeUserFactory;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use IdentityPlatform\Laravel\Users\NativeUserRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Bus\QueueingDispatcher;
use Illuminate\Contracts\Container\Container as HostContainer;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Request;
use LogicException;
use Psr\Container\ContainerInterface;

/** One operation's graph; retained services and late dependencies keep this exact context.
 * @api
 */
final class ConsumerGraph extends Container
{
    public const SERVICES = [
        ApplicationContextManager::class,
        BrowserLifecycle::class,
        AuthStatePresenter::class,
        SessionManager::class,
        AuthorizationClient::class,
        IdentityAccess::class,
        OrdinaryActionRunner::class,
        CallbackReceiver::class,
        CallbackRepository::class,
        IdentityEventVerifier::class,
        LogoutTokenVerifier::class,
        ConsumerClient::class,
        DelegatedActionRepository::class,
        DelegatedActionRunner::class,
        DelegationExecutionGuard::class,
        DelegationManager::class,
        OverlayRepository::class,
        ApplicationContextController::class,
        BrowserController::class,
        CallbackController::class,
        ApiCredential::class,
        BrowserSafety::class,
        DelegationBoundary::class,
        RequireAuthority::class,
        RequireSession::class,
        IdTokenVerifier::class,
        OidcClient::class,
        TrustedProviderMetadata::class,
        LocalProfileManager::class,
        LocalProfileRepository::class,
        LoginRepository::class,
        SessionRepository::class,
        ResourceVerifier::class,
        LocalSessionDirectory::class,
        IdentityConfig::class,
        IdentityHttp::class,
        IdentityVault::class,
        UserImportBootstrap::class,
        UserImportClient::class,
        UserImportMapping::class,
        UserSnapshotClient::class,
        UserSnapshotRepository::class,
        UserSyncManager::class,
        UserSyncWorkRepository::class,
        UserSynchronizer::class,
        EloquentIdentityUserResolver::class,
        EloquentNativeUserFactory::class,
        EloquentNativeUserMapper::class,
        IdentityUserResolver::class,
        NativeUserFactory::class,
        NativeUserMapper::class,
        NativeUserRepository::class,
    ];

    public function __construct(private HostContainer $host, public readonly ConsumerContext $context, Request $request)
    {
        $this->instance(self::class, $this);
        $this->instance(HostContainer::class, $this);
        $this->instance(Container::class, $this);
        $this->instance('app', $this);
        $this->instance(ContainerInterface::class, $this);
        $this->instance(\Symfony\Component\HttpFoundation\Request::class, $request);
        $this->instance('request', $request);
        $this->instance(ConsumerContext::class, $context);
        $this->instance(IdentityConfig::class, new IdentityConfig($context));
        $this->instance(Request::class, $request);
        $resolver = PostContextDestinationResolver::class;
        $binding = $host->getBindings()[$resolver] ?? null;
        if ($binding !== null) {
            ContextDefinition::require(is_array($binding) && isset($binding['concrete'], $binding['shared']) && ($binding['concrete'] instanceof Closure || is_string($binding['concrete'])) && is_bool($binding['shared']), 'consumer_dependency_not_supported');
        }
        $this->bind($resolver, $binding['concrete'] ?? LocalDestinationResolver::class);
        $this->singleton(IdentityAccess::class);
        $this->singleton(IdentityHttp::class, fn () => new IdentityHttp($this->make(IdentityConfig::class)));
        foreach ([IdentityUserResolver::class => ['resolver', EloquentIdentityUserResolver::class], NativeUserFactory::class => ['factory', EloquentNativeUserFactory::class], NativeUserMapper::class => ['mapper', EloquentNativeUserMapper::class]] as $contract => [$key, $default]) {
            $this->bind($contract, $context->value('users')[$key] ?? $default);
        }
    }

    /** @param array<array-key, mixed> $parameters */
    protected function resolve($abstract, $parameters = [], $raiseEvents = true)
    {
        if (! is_string($abstract)) {
            return parent::resolve($abstract, $parameters, $raiseEvents);
        }
        if ($this->bound($abstract)) {
            return parent::resolve($abstract, $parameters, $raiseEvents);
        }
        if (in_array($abstract, [ApplicationContextRegistry::class, Identity::class, ConsumerRegistry::class, ServiceTargetRegistry::class, ExecutionPolicy::class], true)) {
            return $this->host->make($abstract, $parameters);
        }
        if (str_starts_with($abstract, 'IdentityPlatform\\Laravel\\')) {
            $this->bind($abstract);

            return parent::resolve($abstract, $parameters, $raiseEvents);
        }
        $canonical = $this->host->getAlias($abstract);
        if (in_array($canonical, ['config', 'db', 'db.connection', 'cache', 'cache.store', 'events', 'encrypter', 'files', 'filesystem', 'filesystem.disk', 'filesystem.cloud', 'log', 'validator', 'translator', 'queue', 'queue.connection', Dispatcher::class, QueueingDispatcher::class, Factory::class], true)) {
            return $this->host->make($abstract, $parameters);
        }
        if (in_array($canonical, ['app', 'auth', 'auth.driver', 'session', 'session.store', 'cookie'], true)) {
            throw new IdentityException('consumer_dependency_not_supported');
        }
        if ($canonical !== $abstract) {
            return $this->make($canonical, $parameters);
        }
        $binding = $this->host->getBindings()[$abstract] ?? null;
        if ($binding !== null) {
            ContextDefinition::require(is_array($binding) && isset($binding['concrete'], $binding['shared']) && ($binding['concrete'] instanceof Closure || is_string($binding['concrete'])) && is_bool($binding['shared']), 'consumer_dependency_not_supported');
            // Re-run application bindings with this graph, never reuse ambient singletons.
            $this->bind($abstract, $binding['concrete'], $binding['shared']);
        }

        return parent::resolve($abstract, $parameters, $raiseEvents);
    }

    public function __serialize(): array
    {
        throw new LogicException('Consumer graphs cannot be serialized; persist a local row reference.');
    }
}
