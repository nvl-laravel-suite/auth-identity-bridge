<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Profiles\LocalProfileRepository;
use IdentityPlatform\Laravel\Sessions\LocalSessionDirectory;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserProjectionRepository;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Users\HasIdentityAccess;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeOwner;
use IdentityPlatform\Laravel\Users\ProjectionOwnership;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Schema;

class NativeAccount extends User
{
    use HasIdentityAccess;

    protected $table = 'native_accounts';

    protected $guarded = [];
}

class NativeFoundationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->assertTrue(interface_exists(IdentityUserResolver::class), 'Native resolver contract is missing');
        Schema::create('native_accounts', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.users.model' => NativeAccount::class, 'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email'], 'auth.guards.identity' => ['driver' => 'identity'], 'auth.defaults.guard' => 'identity']);
    }

    public function test_native_associations_use_explicit_issuer_subject_and_binding_without_email_linking(): void
    {
        $named = function (string $name): array {
            $definition = config('identity.consumers.one');
            $origin = 'https://'.$name.'.test';
            $definition['origin'] = 'https://other.test';
            $definition['app_origin'] = $origin;
            $definition['browser']['client_id'] = 'web-'.$name;
            $definition['browser']['redirect_uri'] = $origin.'/auth/callback';
            $definition['browser']['post_logout_redirect_uri'] = $origin.'/signed-out';
            $definition['session']['cookie'] = '__Host-'.$name;
            $definition['routes']['guard'] = 'identity_'.$name;
            $definition['routes']['event_uri'] = $origin.'/identity/events';
            $definition['routes']['backchannel_logout_uri'] = $origin.'/auth/backchannel-logout';
            $definition['users']['identity_projection_writer'] = 'two';

            return $definition;
        };
        $this->configure(['identity.consumers.two' => $named('two'), 'identity.consumers.three' => $named('three')]);
        $existing = NativeAccount::query()->create(['email' => 'same@example.test']);
        $first = $this->projection('first');
        $resolver = app(IdentityUserResolver::class);
        $one = $resolver->resolve($first);
        $this->assertInstanceOf(NativeAccount::class, $one);
        $this->assertNotSame($existing->id, $one->id);
        $this->assertSame($one->id, $resolver->resolve($first)->id);
        $two = $resolver->resolve($this->projection('second'));
        $this->assertNotSame($one->id, $two->id);

        $this->selectConsumer('two');
        $foreignIssuer = $this->projection('first');
        $writerBinding = app(IdentityConfig::class)->bindingHash();
        $three = app(IdentityUserResolver::class)->resolve($foreignIssuer);
        $this->assertNotSame($first->id, $foreignIssuer->id);
        $this->assertNotSame($one->id, $three->id);

        $this->selectConsumer('three');
        $anotherBinding = $this->projection('first');
        $four = app(IdentityUserResolver::class)->resolve($anotherBinding);
        $this->assertSame($foreignIssuer->id, $anotherBinding->id);
        $this->assertNotSame($three->id, $four->id);
        $this->assertSame($writerBinding, DB::table('identity_projection_owners')->where('kind', 'common')->where('identity_key', $foreignIssuer->identity_key)->value('writer_binding'));
        $this->assertDatabaseCount('identity_user_links', 4);
        $this->assertDatabaseCount('native_accounts', 5);
    }

    public function test_failed_factory_rolls_back_native_account_and_association(): void
    {
        $this->nativeFactory(function (IdentityUser $projection): NativeAccount {
            NativeAccount::query()->create(['name' => $projection->name]);
            throw new \RuntimeException('private-host-failure');
        });
        try {
            app(IdentityUserResolver::class)->resolve($this->projection('person'));
            $this->fail('Factory failure accepted');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_unavailable', $error->errorCode);
            $this->assertStringNotContainsString('private-host-failure', $error->getMessage());
        }
        $this->assertDatabaseCount('native_accounts', 0);
        $this->assertDatabaseCount('identity_user_links', 0);
    }

    public function test_unique_native_owner_cannot_implicitly_associate_another_subject(): void
    {
        $first = $this->projection('one');
        $account = app(IdentityUserResolver::class)->resolve($first);
        $this->nativeFactory(fn (IdentityUser $projection) => $account);
        try {
            app(IdentityUserResolver::class)->resolve($this->projection('two'));
            $this->fail('An existing native owner was acquired through a factory');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_invalid', $error->errorCode);
        }
        $this->assertDatabaseCount('native_accounts', 1);
        $this->assertDatabaseCount('identity_user_links', 1);
        $this->assertSame($first->id, DB::table('identity_user_links')->sole()->projection_id);
        $this->assertSame((string) $account->id, DB::table('identity_user_links')->sole()->user_id);
        $this->assertSame($account->id, app(IdentityUserResolver::class)->resolve($first)->id);
    }

    public function test_reentrant_association_cannot_publish_duplicate_link_or_orphan_user(): void
    {
        $projection = $this->projection('person');
        $resolver = null;
        $inside = false;
        $this->nativeFactory(function (IdentityUser $projection) use (&$inside, &$resolver): NativeAccount {
            if (! $inside) {
                $inside = true;
                $resolver->resolve($projection);
            }

            return NativeAccount::query()->create(['name' => 'Created']);
        });
        $resolver = app(IdentityUserResolver::class);
        try {
            $resolver->resolve($projection);
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_conflict', $error->errorCode);
        }
        $this->assertLessThanOrEqual(1, DB::table('identity_user_links')->count());
        $this->assertSame(DB::table('identity_user_links')->count(), NativeAccount::query()->count());
    }

    public function test_projection_repository_is_injected_into_synchronizer(): void
    {
        $repository = new class(app(IdentityConfig::class), $this->graph()->make(ProjectionOwnership::class)) extends UserProjectionRepository
        {
            public bool $called = false;

            public function synchronize(string $issuer, string $subject, array $profile): array
            {
                $this->called = true;

                return parent::synchronize($issuer, $subject, $profile);
            }
        };
        $this->graph()->instance(UserProjectionRepository::class, $repository);
        app(UserSynchronizer::class)->sync(['sub' => 'injected']);
        $this->assertTrue($repository->called);
    }

    public function test_host_resolver_is_injected_into_the_native_request_guard(): void
    {
        $projection = $this->projection('person');
        $row = $this->makeSession($projection, 'mine');
        $account = NativeAccount::query()->create(['name' => 'Host resolved']);
        $this->graph()->instance(IdentityUserResolver::class, new class($account) implements IdentityUserResolver
        {
            public function __construct(private NativeAccount $account) {}

            public function resolve(IdentityUser $projection): Authenticatable
            {
                return $this->account;
            }
        });
        $this->bindRequest($this->browser($row->id));
        $this->assertSame($account->id, Auth::user()->id);
        $this->assertDatabaseCount('identity_user_links', 0);
    }

    public function test_native_factory_cannot_silently_use_another_database_connection(): void
    {
        $this->configure(['database.connections.another' => config('database.connections.sqlite')]);
        $owner = new NativeAccount;
        $owner->setConnection('another');
        $owner->id = 1;
        $owner->exists = true;
        $this->nativeFactory(fn (IdentityUser $projection) => $owner);
        $this->expectExceptionObject(new IdentityException('identity_user_invalid', 409));
        app(IdentityUserResolver::class)->resolve($this->projection('person'));
    }

    public function test_owner_keys_distinguish_model_connections_even_with_the_same_identifier(): void
    {
        $first = NativeAccount::query()->create(['name' => 'First']);
        $this->configure(['database.connections.another' => config('database.connections.sqlite')]);
        $second = clone $first;
        $second->setConnection('another');
        $this->assertNotSame(NativeOwner::key($first), NativeOwner::key($second));
    }

    public function test_native_guard_and_gates_keep_resource_ownership_and_request_state_isolation(): void
    {
        $projection = $this->projection('person');
        $row = $this->makeSession($projection, 'first');
        $first = $this->browser($row->id);
        $this->bindRequest($first);
        $user = Auth::user();
        $this->assertInstanceOf(NativeAccount::class, $user);
        Gate::define('documents.update', fn (NativeAccount $account, int $owner) => $account->identityAccess()->hasPermission('documents.update') && $account->id === $owner);
        $this->assertTrue($user->can('documents.update', $user->id));
        $this->assertFalse($user->can('documents.update', $user->id + 1));
        $access = app(IdentityAccess::class);
        $this->assertSame($user->id, $access->actor()->id);
        $this->assertSame('organization-1', $access->organizationId());
        $this->assertFalse($access->hasPermission('unknown.permission'));
        $this->bindRequest($this->browser());
        $this->assertNull(Auth::user());
        $this->assertNull($access->user());
        $this->assertNull($access->actor());
        $this->assertNull($access->projection());
    }

    public function test_local_profile_revisions_are_independent_and_reject_stale_or_shared_fields(): void
    {
        $owner = app(IdentityUserResolver::class)->resolve($this->projection('person'));
        $repository = app(LocalProfileRepository::class);
        $profile = $repository->read($owner);
        $this->assertSame(1, $profile->version);
        $this->assertTrue(method_exists($repository, 'lock'), 'Owned profile row locking is missing');
        $this->assertSame($profile->id, $repository->lock($owner)->id);
        $changed = $repository->update($owner, 1, ['display_name' => 'Local name', 'preferences' => ['digest' => false]]);
        $this->assertSame(2, $changed->version);
        $this->assertSame('Local name', $changed->display_name);
        try {
            $repository->update($owner, 1, ['display_name' => 'Stale name']);
            $this->fail('Stale profile write accepted');
        } catch (IdentityException $error) {
            $this->assertSame('profile_changed', $error->errorCode);
        }
        try {
            $repository->update($owner, 2, ['email' => 'other@example.test']);
            $this->fail('Shared field written locally');
        } catch (IdentityException $error) {
            $this->assertSame('profile_invalid', $error->errorCode);
        }
        $this->assertSame('same@example.test', $owner->fresh()->email);
        $this->assertSame(2, $repository->read($owner)->version);
        $this->configure(['identity.consumers.one.browser.client_id' => 'another-client']);
        $this->assertSame(2, $repository->read($owner)->version);
        $this->assertSame(1, app(LocalProfileRepository::class)->read($owner)->version);
    }

    public function test_session_directory_only_returns_sanitized_owned_binding_rows_and_revoke_is_scoped(): void
    {
        $first = $this->projection('person');
        $other = $this->projection('other');
        $owner = app(IdentityUserResolver::class)->resolve($first);
        $mine = $this->makeSession($first, 'mine');
        $foreignOwner = $this->makeSession($other, 'foreign');
        $foreignBinding = $this->makeSession($first, 'another-binding');
        $foreignBinding->update(['binding_hash' => str_repeat('f', 64)]);
        $this->bindRequest($this->browser($mine->id));
        $directory = app(LocalSessionDirectory::class);
        $entries = $directory->forOwner($owner);
        $this->assertCount(1, $entries);
        $this->assertSame($mine->id, $entries[0]['id']);
        $this->assertTrue($entries[0]['current']);
        $this->assertSame(['id', 'started_at', 'last_activity_at', 'expires_at', 'current'], array_keys($entries[0]));
        $this->assertTrue(method_exists($directory, 'lock'), 'Owned session row locking is missing');
        $this->assertSame($mine->id, $directory->lock($owner, $mine->id)->id);
        $this->assertNull($directory->lock($owner, $foreignOwner->id));
        $this->assertNull($directory->lock($owner, $foreignBinding->id));
        $this->assertFalse($directory->revoke($owner, $foreignOwner->id));
        $this->assertFalse($directory->revoke($owner, $foreignBinding->id));
        $this->assertTrue($directory->revoke($owner, $mine->id));
        $this->assertDatabaseCount('identity_sessions', 2);
    }

    public function test_fresh_account_write_rejects_stale_context_before_fetching_authority(): void
    {
        $projection = $this->projection('person');
        $row = $this->makeSession($projection, 'mine');
        $request = $this->browser($row->id, 'POST');
        $request->request->set('context_version', 1);
        $this->bindRequest($request);
        $this->expectExceptionObject(new IdentityException('context_changed', 409));
        app(IdentityAccess::class)->assertFreshContext();
    }

    public function test_native_policy_permission_on_a_write_cannot_reuse_a_cached_read_decision(): void
    {
        $projection = $this->projection('person');
        $row = $this->makeSession($projection, 'mine');
        $request = $this->browser($row->id, 'POST');
        $request->request->set('context_version', 1);
        $this->bindRequest($request);
        $this->expectExceptionObject(new IdentityException('context_changed', 409));
        app(IdentityAccess::class)->hasPermission('documents.update');
    }

    public function test_trait_on_another_native_owner_never_inherits_current_browser_permissions(): void
    {
        $projection = $this->projection('person');
        $row = $this->makeSession($projection, 'mine');
        $this->bindRequest($this->browser($row->id));
        $other = NativeAccount::query()->create(['name' => 'Other']);
        $this->expectExceptionObject(new IdentityException('access_denied', 403));
        $other->identityAccess();
    }

    private function projection(string $subject): IdentityUser
    {
        return app(UserSynchronizer::class)->sync(['sub' => $subject, 'email' => 'same@example.test', 'name' => 'Central name']);
    }

    private function makeSession(IdentityUser $projection, string $id): IdentitySession
    {
        return IdentitySession::query()->create([
            'id' => $id, 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'user_id' => $projection->id,
            'subject' => $projection->subject, 'sid' => 'central',
            'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:'.$id),
            'selection' => ['selected' => true, 'organizationId' => 'organization-1'],
            'snapshot' => ['contract' => 'platform-authorization-snapshot.v1', 'subject' => $projection->subject, 'organization_id' => 'organization-1', 'permissions' => ['documents.update'], 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59)],
            'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour(),
        ]);
    }

    private function browser(?string $id = null, string $method = 'GET'): Request
    {
        $request = Request::create('https://consumer.test/', $method);
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        if ($id) {
            $store->put('identity.session', $id);
        }
        $request->setLaravelSession($store);

        return $request;
    }
}
