# Public API: nvl/auth-identity-bridge

Generated from the package public contract. Use this reference to confirm fully qualified names, parameter order, defaults, native array shapes and return types. Read [usage](usage.md) for policy and operation semantics; declarations alone never grant authority.

Search for the relevant fully qualified service or contract and read only its matching symbol sections; this is a lookup catalog, not an instruction to load every declaration. `resolved` annotations expand imported aliases and domain type shapes. Framework inheritance and host-authored extensions remain outside this package contract.

## Symbols

- `IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager`
- `IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry`
- `IdentityPlatform\Laravel\Auth\BrowserLifecycle`
- `IdentityPlatform\Laravel\Authorization\AbilityRegistry`
- `IdentityPlatform\Laravel\Authorization\IdentityAccess`
- `IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner`
- `IdentityPlatform\Laravel\Consumer\CommandJournal`
- `IdentityPlatform\Laravel\Consumer\ConsumerClient`
- `IdentityPlatform\Laravel\Consumer\ManagedOperations`
- `IdentityPlatform\Laravel\Delegation\DelegatedActionRunner`
- `IdentityPlatform\Laravel\Facades\Identity`
- `IdentityPlatform\Laravel\Identity`
- `IdentityPlatform\Laravel\Services\ServiceTokenClient`
- `IdentityPlatform\Laravel\Services\ServiceTokenManager`
- `IdentityPlatform\Laravel\Support\ConsumerGraph`
- `IdentityPlatform\Laravel\Sync\ImportRunner`
- `IdentityPlatform\Laravel\Sync\UserImportSourceRegistry`
- `IdentityPlatform\Laravel\Sync\UserSyncManager`
- `IdentityPlatform\Laravel\Users\NativeUserFactory`
- `IdentityPlatform\Laravel\Users\NativeUserMapper`

## IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager

```text
final class IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager
public function __construct(IdentityPlatform\Laravel\Auth\SessionManager $sessions, IdentityPlatform\Laravel\Repositories\SessionRepository $rows, IdentityPlatform\Laravel\Delegation\OverlayRepository $overlays, IdentityPlatform\Laravel\Support\IdentityConfig $config, IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry $registry, IdentityPlatform\Laravel\Support\ConsumerGraph $graph, IdentityPlatform\Laravel\Auth\BrowserCommand $commands): mixed
public function assertEligible(Illuminate\Http\Request $request, IdentityPlatform\Laravel\Authorization\Principal $principal): IdentityPlatform\Laravel\ApplicationContext\ApplicationContextDescriptor
public function clear(Illuminate\Http\Request $request): void
public function current(Illuminate\Http\Request $request): ?IdentityPlatform\Laravel\ApplicationContext\ApplicationContextDescriptor
public function forSource(IdentityPlatform\Laravel\Models\IdentitySession $row): ?IdentityPlatform\Laravel\ApplicationContext\ApplicationContextDescriptor
public function list(Illuminate\Http\Request $request, string $kind): array
@return list<ApplicationContextDescriptor>
resolved @return list<IdentityPlatform\Laravel\ApplicationContext\ApplicationContextDescriptor>
public function select(Illuminate\Http\Request $request): IdentityPlatform\Laravel\ApplicationContext\ApplicationContextDescriptor
```

## IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry

```text
final class IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry
public function provider(string $consumer, string $kind): string
@return class-string<ApplicationContextProvider>
resolved @return class-string<IdentityPlatform\Laravel\ApplicationContext\ApplicationContextProvider>
public function register(string $consumer, string $kind, string $provider): void
@param string $provider
```

## IdentityPlatform\Laravel\Auth\BrowserLifecycle

```text
final class IdentityPlatform\Laravel\Auth\BrowserLifecycle
public function __construct(IdentityPlatform\Laravel\Auth\SessionManager $sessions, IdentityPlatform\Laravel\Support\IdentityConfig $config, IdentityPlatform\Laravel\Auth\PostContextDestinationResolver $destinations, IdentityPlatform\Laravel\Auth\AuthStatePresenter $presenter, IdentityPlatform\Laravel\Auth\BrowserCommand $commands): mixed
public function centralSignOut(Illuminate\Http\Request $request): string
public function completeSignIn(Illuminate\Http\Request $request): string
public function discoverContexts(Illuminate\Http\Request $request): array
@return array{contexts: list<ContextOption>, contextVersion: int}
resolved @return array{contexts: list<array{selection: array{organizationId?: string, roleId?: string}, applicationName: string, organizationName: (string | null), roleName: (string | null)}>, contextVersion: int}
public function finishLogout(Illuminate\Http\Request $request): void
public function selectContext(Illuminate\Http\Request $request): IdentityPlatform\Laravel\Auth\BrowserDestination
public function signOut(Illuminate\Http\Request $request): void
public function startSignIn(Illuminate\Http\Request $request, mixed $returnPath="/", bool $resource=false): string
public function state(): IdentityPlatform\Laravel\Auth\AuthStateView
```

## IdentityPlatform\Laravel\Authorization\AbilityRegistry

```text
final class IdentityPlatform\Laravel\Authorization\AbilityRegistry
public function family(string $prefix): self
public function map(string $ability, string $permission, string $policy, string $method): self
@param class-string $policy
public function mapping(string $ability): ?array
@return (Mapping | null)
resolved @return (array{permission: string, policy: class-string, method: string} | null)
public function owns(string $ability): bool
```

## IdentityPlatform\Laravel\Authorization\IdentityAccess

```text
class IdentityPlatform\Laravel\Authorization\IdentityAccess
public function __construct(IdentityPlatform\Laravel\Support\ConsumerGraph $graph, Illuminate\Http\Request $request, IdentityPlatform\Laravel\Auth\SessionManager $sessions, IdentityPlatform\Laravel\Sync\UserProjectionRepository $projections, IdentityPlatform\Laravel\Users\IdentityUserResolver $resolver, IdentityPlatform\Laravel\Delegation\OverlayRepository $overlays): mixed
public function actor(): ?Illuminate\Contracts\Auth\Authenticatable
public function assertFreshContext(): IdentityPlatform\Laravel\Authorization\Principal
public function assertOwner(Illuminate\Contracts\Auth\Authenticatable $owner): void
public function contextVersion(): ?int
public function currentDecisionView(): IdentityPlatform\Laravel\Authorization\CurrentDecisionView
public function hasPermission(string $permission, bool $fresh=false): bool
public function hasSelectedRole(string $role, bool $fresh=false): bool
public function isImpersonating(): bool
public function organizationId(): ?string
public function principal(bool $fresh=false): IdentityPlatform\Laravel\Authorization\Principal
public function projection(): ?IdentityPlatform\Laravel\Models\IdentityUser
public function setRequest(Illuminate\Http\Request $request): void
public function user(): ?Illuminate\Contracts\Auth\Authenticatable
```

## IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner

```text
class IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner
public function __construct(IdentityPlatform\Laravel\Auth\SessionManager $sessions, IdentityPlatform\Laravel\Repositories\SessionRepository $rows, IdentityPlatform\Laravel\Delegation\OverlayRepository $overlays, IdentityPlatform\Laravel\Support\IdentityConfig $config): mixed
public function run(Illuminate\Http\Request $request, Closure $lockResource, Closure $mutate): mixed
@template TResource
@template TResult
@param Closure(): TResource $lockResource
@param Closure(TResource, Principal): TResult $mutate
resolved @param Closure(TResource, IdentityPlatform\Laravel\Authorization\Principal): TResult $mutate
@return TResult
template IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner::TResource
template IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner::TResult
```

## IdentityPlatform\Laravel\Consumer\CommandJournal

```text
class IdentityPlatform\Laravel\Consumer\CommandJournal
public function __construct(IdentityPlatform\Laravel\Support\IdentityConfig $config, IdentityPlatform\Laravel\Sync\UserSyncManager $sync, IdentityPlatform\Laravel\Sync\UserSyncWorkRepository $work): mixed
public function committed(array $reference, array $receipt): IdentityPlatform\Laravel\Consumer\ConsumerCommand
@param array<array-key, mixed> $reference
@param array<array-key, mixed> $receipt
public function forActor(IdentityPlatform\Laravel\Models\IdentitySession $actor, string $key): array
@return CommandReference
resolved @return array{contract: 'platform-consumer-command-reference.v1', bindingHash: string, issuer: string, applicationId: string, clientId: string, localSessionId: non-empty-string, subject: non-empty-string, centralSessionId: non-empty-string, organizationId: (non-empty-string | null), roleId: (non-empty-string | null), contextVersion: int<0, max>, operation: ('users.profile.update' | 'users.metadata.update'), userId: non-empty-string, expectedVersion: positive-int, idempotencyKey: non-empty-string, changedFields: non-empty-list<non-empty-string>}
public function original(array $reference): IdentityPlatform\Laravel\Consumer\ConsumerCommand
@param array<array-key, mixed> $reference
public function pendingRefreshIds(int $limit=100): array
@return array<array-key, mixed>
public function refresh(string $id, bool $process=true): string
public function retain(array $reference): IdentityPlatform\Laravel\Consumer\ConsumerCommand
@param array<array-key, mixed> $reference
public function state(array $reference, string $state): void
@param array<array-key, mixed> $reference
public function validate(array $reference): void
@param array<array-key, mixed> $reference
@phpstan-assert CommandReference $reference
resolved @phpstan-assert array{contract: 'platform-consumer-command-reference.v1', bindingHash: string, issuer: string, applicationId: string, clientId: string, localSessionId: non-empty-string, subject: non-empty-string, centralSessionId: non-empty-string, organizationId: (non-empty-string | null), roleId: (non-empty-string | null), contextVersion: int<0, max>, operation: ('users.profile.update' | 'users.metadata.update'), userId: non-empty-string, expectedVersion: positive-int, idempotencyKey: non-empty-string, changedFields: non-empty-list<non-empty-string>} $reference
```

## IdentityPlatform\Laravel\Consumer\ConsumerClient

```text
class IdentityPlatform\Laravel\Consumer\ConsumerClient
public function __construct(IdentityPlatform\Laravel\Auth\SessionManager $sessions, IdentityPlatform\Laravel\Repositories\SessionRepository $rows, IdentityPlatform\Laravel\Support\IdentityVault $vault, IdentityPlatform\Laravel\Support\IdentityConfig $config, IdentityPlatform\Laravel\Support\IdentityHttp $http, IdentityPlatform\Laravel\Delegation\OverlayRepository $overlays, IdentityPlatform\Laravel\Consumer\CommandJournal $commands): mixed
public function call(Illuminate\Http\Request $request, string $operation, array $input=[]): array
@param array<array-key, mixed> $input
@return array<array-key, mixed>
public function operationStatus(Illuminate\Http\Request $request, array $reference): IdentityPlatform\Laravel\Consumer\ManagedCommandResult
@param array<array-key, mixed> $reference
public function readMetadata(Illuminate\Http\Request $request, array $input): IdentityPlatform\Laravel\Consumer\ManagedReadResult
@param array<array-key, mixed> $input
public function readProfile(Illuminate\Http\Request $request, array $input): IdentityPlatform\Laravel\Consumer\ManagedReadResult
@param array<array-key, mixed> $input
public function report(array $receipt, string $outcome, ?string $resultCode=null): array
@param array<array-key, mixed> $receipt
@return array<array-key, mixed>
public function updateMetadata(Illuminate\Http\Request $request, #[SensitiveParameter()] array $input): IdentityPlatform\Laravel\Consumer\ManagedCommandResult
@param array<array-key, mixed> $input
public function updateProfile(Illuminate\Http\Request $request, #[SensitiveParameter()] array $input): IdentityPlatform\Laravel\Consumer\ManagedCommandResult
@param array<array-key, mixed> $input
```

## IdentityPlatform\Laravel\Consumer\ManagedOperations

```text
trait IdentityPlatform\Laravel\Consumer\ManagedOperations
public function operationStatus(Illuminate\Http\Request $request, array $reference): IdentityPlatform\Laravel\Consumer\ManagedCommandResult
@param array<array-key, mixed> $reference
public function readMetadata(Illuminate\Http\Request $request, array $input): IdentityPlatform\Laravel\Consumer\ManagedReadResult
@param array<array-key, mixed> $input
public function readProfile(Illuminate\Http\Request $request, array $input): IdentityPlatform\Laravel\Consumer\ManagedReadResult
@param array<array-key, mixed> $input
public function updateMetadata(Illuminate\Http\Request $request, #[SensitiveParameter()] array $input): IdentityPlatform\Laravel\Consumer\ManagedCommandResult
@param array<array-key, mixed> $input
public function updateProfile(Illuminate\Http\Request $request, #[SensitiveParameter()] array $input): IdentityPlatform\Laravel\Consumer\ManagedCommandResult
@param array<array-key, mixed> $input
```

## IdentityPlatform\Laravel\Delegation\DelegatedActionRunner

```text
class IdentityPlatform\Laravel\Delegation\DelegatedActionRunner
public function __construct(IdentityPlatform\Laravel\Delegation\DelegationManager $delegations, IdentityPlatform\Laravel\Auth\SessionManager $sessions, IdentityPlatform\Laravel\Delegation\OverlayRepository $overlays, IdentityPlatform\Laravel\Delegation\DelegatedActionRepository $actions, IdentityPlatform\Laravel\Consumer\ConsumerClient $client, IdentityPlatform\Laravel\Support\IdentityVault $vault, IdentityPlatform\Laravel\Support\IdentityConfig $config): mixed
public function run(Illuminate\Http\Request $request, string $operation, string $resourceType, string $resourceId, array $command, string $idempotencyKey, Closure $lockResource, Closure $mutate): array
@param array<array-key, mixed> $command
@param Closure(): mixed $lockResource
@param Closure(mixed): mixed $mutate
@return array<array-key, mixed>
```

## IdentityPlatform\Laravel\Facades\Identity

```text
class IdentityPlatform\Laravel\Facades\Identity extends Illuminate\Support\Facades\Facade
@mixin IdentityAccess
resolved @mixin IdentityPlatform\Laravel\Authorization\IdentityAccess
public static function browser(): IdentityPlatform\Laravel\Auth\BrowserLifecycle
public static function consumer(string $name, ?Illuminate\Http\Request $request=null): IdentityPlatform\Laravel\Support\ConsumerGraph
```

## IdentityPlatform\Laravel\Identity

```text
final readonly class IdentityPlatform\Laravel\Identity
public function __construct(Illuminate\Contracts\Container\Container $app, IdentityPlatform\Laravel\Support\ConsumerRegistry $registry): mixed
public function browser(): IdentityPlatform\Laravel\Auth\BrowserLifecycle
public function byBinding(string $binding): IdentityPlatform\Laravel\Support\ConsumerGraph
public function consumer(string $name, ?Illuminate\Http\Request $request=null): IdentityPlatform\Laravel\Support\ConsumerGraph
```

## IdentityPlatform\Laravel\Services\ServiceTokenClient

```text
final class IdentityPlatform\Laravel\Services\ServiceTokenClient
public function __construct(IdentityPlatform\Laravel\Support\ServiceTargetContext $config, IdentityPlatform\Laravel\Support\IdentityHttp $http): mixed
public function reject(#[SensitiveParameter()] string $token, array $scopes=[]): void
@param array<array-key, mixed> $scopes
public function request(string $relativePath, array $options=[]): Psr\Http\Message\ResponseInterface
@param array<array-key, mixed> $options
public function revoke(#[SensitiveParameter()] string $token): void
public function token(array $scopes=[]): string
@param array<array-key, mixed> $scopes
```

## IdentityPlatform\Laravel\Services\ServiceTokenManager

```text
final readonly class IdentityPlatform\Laravel\Services\ServiceTokenManager
public function __construct(IdentityPlatform\Laravel\Support\ServiceTargetRegistry $targets): mixed
public function target(string $name): IdentityPlatform\Laravel\Services\ServiceTokenClient
```

## IdentityPlatform\Laravel\Support\ConsumerGraph

```text
final class IdentityPlatform\Laravel\Support\ConsumerGraph extends Illuminate\Container\Container
public const mixed SERVICES=[\IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager::class, \IdentityPlatform\Laravel\Auth\BrowserLifecycle::class, \IdentityPlatform\Laravel\Auth\AuthStatePresenter::class, \IdentityPlatform\Laravel\Auth\SessionManager::class, \IdentityPlatform\Laravel\Authorization\AuthorizationClient::class, \IdentityPlatform\Laravel\Authorization\IdentityAccess::class, \IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner::class, \IdentityPlatform\Laravel\Callbacks\CallbackReceiver::class, \IdentityPlatform\Laravel\Callbacks\CallbackRepository::class, \IdentityPlatform\Laravel\Callbacks\IdentityEventVerifier::class, \IdentityPlatform\Laravel\Callbacks\LogoutTokenVerifier::class, \IdentityPlatform\Laravel\Consumer\ConsumerClient::class, \IdentityPlatform\Laravel\Delegation\DelegatedActionRepository::class, \IdentityPlatform\Laravel\Delegation\DelegatedActionRunner::class, \IdentityPlatform\Laravel\Delegation\DelegationExecutionGuard::class, \IdentityPlatform\Laravel\Delegation\DelegationManager::class, \IdentityPlatform\Laravel\Delegation\OverlayRepository::class, \IdentityPlatform\Laravel\Http\Controllers\ApplicationContextController::class, \IdentityPlatform\Laravel\Http\Controllers\BrowserController::class, \IdentityPlatform\Laravel\Http\Controllers\CallbackController::class, \IdentityPlatform\Laravel\Http\Middleware\ApiCredential::class, \IdentityPlatform\Laravel\Http\Middleware\BrowserSafety::class, \IdentityPlatform\Laravel\Http\Middleware\DelegationBoundary::class, \IdentityPlatform\Laravel\Http\Middleware\RequireAuthority::class, \IdentityPlatform\Laravel\Http\Middleware\RequireSession::class, \IdentityPlatform\Laravel\Oidc\IdTokenVerifier::class, \IdentityPlatform\Laravel\Oidc\OidcClient::class, \IdentityPlatform\Laravel\Oidc\TrustedProviderMetadata::class, \IdentityPlatform\Laravel\Profiles\LocalProfileManager::class, \IdentityPlatform\Laravel\Profiles\LocalProfileRepository::class, \IdentityPlatform\Laravel\Repositories\LoginRepository::class, \IdentityPlatform\Laravel\Repositories\SessionRepository::class, \IdentityPlatform\Laravel\Services\ResourceVerifier::class, \IdentityPlatform\Laravel\Sessions\LocalSessionDirectory::class, \IdentityPlatform\Laravel\Support\IdentityConfig::class, \IdentityPlatform\Laravel\Support\IdentityHttp::class, \IdentityPlatform\Laravel\Support\IdentityVault::class, \IdentityPlatform\Laravel\Sync\UserImportBootstrap::class, \IdentityPlatform\Laravel\Sync\UserImportClient::class, \IdentityPlatform\Laravel\Sync\UserImportMapping::class, \IdentityPlatform\Laravel\Sync\UserSnapshotClient::class, \IdentityPlatform\Laravel\Sync\UserSnapshotRepository::class, \IdentityPlatform\Laravel\Sync\UserSyncManager::class, \IdentityPlatform\Laravel\Sync\UserSyncWorkRepository::class, \IdentityPlatform\Laravel\Sync\UserSynchronizer::class, \IdentityPlatform\Laravel\Users\EloquentIdentityUserResolver::class, \IdentityPlatform\Laravel\Users\EloquentNativeUserFactory::class, \IdentityPlatform\Laravel\Users\EloquentNativeUserMapper::class, \IdentityPlatform\Laravel\Users\IdentityUserResolver::class, \IdentityPlatform\Laravel\Users\NativeUserFactory::class, \IdentityPlatform\Laravel\Users\NativeUserMapper::class, \IdentityPlatform\Laravel\Users\NativeUserRepository::class]
public function __construct(Illuminate\Contracts\Container\Container $host, IdentityPlatform\Laravel\Support\ConsumerContext $context, Illuminate\Http\Request $request): mixed
public function __serialize(): array
public readonly IdentityPlatform\Laravel\Support\ConsumerContext $context
```

## IdentityPlatform\Laravel\Sync\ImportRunner

```text
class IdentityPlatform\Laravel\Sync\ImportRunner
public function __construct(IdentityPlatform\Laravel\Support\IdentityConfig $config, IdentityPlatform\Laravel\Sync\ImportPreflight $preflight, IdentityPlatform\Laravel\Sync\ImportCheckpointRepository $checkpoints, IdentityPlatform\Laravel\Sync\UserImportClient $client, IdentityPlatform\Laravel\Sync\UserImportBootstrap $bootstrap, IdentityPlatform\Laravel\Sync\UserSnapshotRepository $snapshots): mixed
public function __serialize(): array
public function run(string $sourceName, #[SensitiveParameter()] IdentityPlatform\Laravel\Sync\UserImportSource $source, ?string $resume=null, bool $dryRun=false, int $limit=100, int $maxPages=1000): array
@return (array{runId: string, imported: int, associated: int, applied: int, stale: int, missing: int, pending: int, nativePending: int, unresolved: int, failed: int, error: (string | null), exhausted: bool, completed: bool, providerAcceptedInLastAttempt: int, remoteOutcome: string, failedBatch: list<array{sourceUserId: string, nativeUserId: string}>} | array{runId: string, remoteOutcome: string, providerAcceptedInLastAttempt: int, completed: false, error: string, checkpointStatus: string, failedBatch: list<array{sourceUserId: string, nativeUserId: string}>} | array{runId: null, dryRun: true, validated: int, exhausted: bool, completed: false, remoteChecks: string})
public static function safeCode(Throwable $error): string
```

## IdentityPlatform\Laravel\Sync\UserImportSourceRegistry

```text
final class IdentityPlatform\Laravel\Sync\UserImportSourceRegistry
public function register(string $name, string $class): void
public function resolve(string $name, IdentityPlatform\Laravel\Support\ConsumerGraph $graph): IdentityPlatform\Laravel\Sync\UserImportSource
```

## IdentityPlatform\Laravel\Sync\UserSyncManager

```text
class IdentityPlatform\Laravel\Sync\UserSyncManager
public function __construct(IdentityPlatform\Laravel\Support\IdentityConfig $config, IdentityPlatform\Laravel\Sync\UserSnapshotClient $client, IdentityPlatform\Laravel\Sync\UserSnapshotRepository $snapshots, IdentityPlatform\Laravel\Sync\UserSyncWorkRepository $work, IdentityPlatform\Laravel\Sync\ImportCheckpointRepository $imports): mixed
public function process(string $requestId): void
public function reconcile(int $limit=100): array
@return array{imported: int, associated: int, unresolvedImports: int, applied: int, stale: int, failed: int, profiles: int, known: int, missing: int, nativePending: int, nextCursor: (string | null), knownCursor: (string | null), pending: int, completed: bool}
public function request(string $subject): string
public function requestBinding(): string
```

## IdentityPlatform\Laravel\Users\NativeUserFactory

```text
interface IdentityPlatform\Laravel\Users\NativeUserFactory
public abstract function create(IdentityPlatform\Laravel\Models\IdentityUser $projection): Illuminate\Contracts\Auth\Authenticatable
```

## IdentityPlatform\Laravel\Users\NativeUserMapper

```text
interface IdentityPlatform\Laravel\Users\NativeUserMapper
public abstract function synchronize(Illuminate\Contracts\Auth\Authenticatable $user, IdentityPlatform\Laravel\Models\IdentityUser $projection): void
```
