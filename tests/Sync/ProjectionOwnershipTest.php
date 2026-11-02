<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityProjectionOwner;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserImportBootstrap;
use IdentityPlatform\Laravel\Sync\UserImportResult;
use IdentityPlatform\Laravel\Sync\UserProjectionRepository;
use IdentityPlatform\Laravel\Sync\UserSnapshot;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Sync\UserSyncBinding;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Sync\UserSyncRequest;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeUserAssociation;
use IdentityPlatform\Laravel\Users\ProjectionOwnership;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class SharingUser extends User
{
    protected $table = 'sharing_users';

    protected $guarded = [];
}
class SharingAliasUser extends SharingUser {}
class SeparateUser extends SharingUser
{
    protected $table = 'separate_users';
}
class ProjectionOwnershipTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        foreach (['sharing_users', 'separate_users'] as $table) {
            Schema::create($table, function (Blueprint $t): void {
                $t->id();
                $t->string('name');
                $t->string('email');
                $t->timestamps();
            });
        }
        $second = config('identity.consumers.one');
        $second['app_origin'] = 'https://second.test';
        $second['application_id'] = 'app-2';
        $second['browser']['client_id'] = 'web-2';
        $second['browser']['redirect_uri'] = 'https://second.test/auth/callback';
        $second['browser']['post_logout_redirect_uri'] = 'https://second.test/signed-out';
        $second['routes']['event_uri'] = 'https://second.test/identity/events';
        $second['routes']['backchannel_logout_uri'] = 'https://second.test/auth/backchannel-logout';
        $second['routes']['guard'] = 'identity_two';
        $second['session']['cookie'] = '__Host-two';
        $this->configure(['identity.consumers.two' => $second, 'identity.consumers.one.users.model' => SharingUser::class, 'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email'], 'identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.provision_missing' => true, 'identity.consumers.two.users.model' => SeparateUser::class, 'identity.consumers.two.users.fields' => ['name' => 'name', 'email' => 'email'], 'identity.consumers.two.sync.enabled' => true, 'identity.consumers.two.sync.provision_missing' => true]);
    }

    private function proof(int $version, string $name = 'One'): UserSnapshot
    {
        return UserSnapshot::validate(['subject' => 'person', 'version' => $version, 'state' => 'active', 'profile' => ProfileFixture::profile(['name' => $name])], 1, app(IdentityConfig::class));
    }

    public function test_common_projection_has_one_writer_but_separate_native_rows_use_own_binding_facts(): void
    {
        app(UserSnapshotRepository::class)->apply($this->proof(1));
        $this->selectConsumer('two');
        app(UserSnapshotRepository::class)->apply($this->proof(99, 'Two'));
        $this->assertSame('One', IdentityUser::firstOrFail()->name);
        $this->assertSame('One', SharingUser::firstOrFail()->name);
        $this->assertSame('Two', SeparateUser::firstOrFail()->name);
        $this->assertSame('Two', app(UserProjectionRepository::class)->find(IdentityUser::firstOrFail()->id)->name);
        $this->assertSame('Two', app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Old JIT'])->name);
        $this->assertSame('One', IdentityUser::firstOrFail()->name);
    }

    public function test_unmapped_nonwriter_jit_does_not_borrow_or_change_common_facts(): void
    {
        $this->configure(['identity.consumers.one.users.model' => null, 'identity.consumers.one.users.fields' => [], 'identity.consumers.one.sync.provision_missing' => false, 'identity.consumers.two.users.model' => null, 'identity.consumers.two.users.fields' => [], 'identity.consumers.two.sync.provision_missing' => false]);
        app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'One']);
        $this->selectConsumer('two');
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Two']);
        $this->assertSame('Two', $projection->name);
        $this->assertSame('One', IdentityUser::firstOrFail()->name);
        $this->assertSame('Two', app(IdentityUserResolver::class)->resolve($projection)->name);
    }

    private function group(): void
    {
        $group = ['name' => 'people', 'writer' => 'two', 'epoch' => 1];
        $this->configure(['identity.consumers.one.users.native_group' => $group, 'identity.consumers.two.users.native_group' => $group, 'identity.consumers.two.users.model' => SharingAliasUser::class, 'identity.consumers.one.sync.provision_missing' => false, 'identity.consumers.two.sync.provision_missing' => true]);
    }

    public function test_explicit_same_person_group_link_allows_distinct_native_and_common_writers(): void
    {
        $this->group();
        app(UserSnapshotRepository::class)->apply($this->proof(1));
        $target = $this->proof(1);
        $this->selectConsumer('two');
        $proof = $this->proof(5, 'Two');
        app(UserSnapshotRepository::class)->apply($proof);
        $binding = app(IdentityConfig::class)->bindingHash();
        $id = SharingUser::firstOrFail()->id;
        $this->selectConsumer('one');
        $service = $this->graph()->make(NativeUserAssociation::class);
        $this->assertSame($id, $service->associate($target, $binding, $id)->getAuthIdentifier());
        app(UserSnapshotRepository::class)->apply($target);
        $this->assertSame('Two', SharingUser::firstOrFail()->name);
        $this->assertSame('One', IdentityUser::firstOrFail()->name);
        app(UserSnapshotRepository::class)->apply($this->proof(2, 'One later'));
        $this->assertSame('Two', SharingUser::firstOrFail()->name);
        $this->assertSame('One later', IdentityUser::firstOrFail()->name);
        $this->assertSame(1, SharingUser::count());
    }

    public function test_group_does_not_allow_arbitrary_native_id(): void
    {
        $this->group();
        app(UserSnapshotRepository::class)->apply($this->proof(1));
        $target = $this->proof(1);
        $this->selectConsumer('two');
        app(UserSnapshotRepository::class)->apply($this->proof(5, 'Two'));
        $binding = app(IdentityConfig::class)->bindingHash();
        $other = SharingUser::create(['name' => 'Other', 'email' => 'other@example.test']);
        $this->selectConsumer('one');
        $this->expectExceptionObject(new IdentityException('identity_native_proof_invalid', 409));
        $this->graph()->make(NativeUserAssociation::class)->associate($target, $binding, $other->id);
    }

    public function test_changed_common_writer_or_epoch_refuses_instead_of_transferring(): void
    {
        app(UserSnapshotRepository::class)->apply($this->proof(1));
        $this->configure(['identity.consumers.one.users.identity_projection_writer' => 'two', 'identity.consumers.two.users.identity_projection_writer' => 'two']);
        $this->selectConsumer('two');
        $this->expectExceptionObject(new IdentityException('identity_projection_owner_fenced', 409));
        app(UserSnapshotRepository::class)->apply($this->proof(2, 'Two'));
    }

    public function test_explicit_handoff_api_refuses_under_current_owner_lock(): void
    {
        app(UserSnapshotRepository::class)->apply($this->proof(1));
        $owner = IdentityProjectionOwner::where('kind', 'common')->firstOrFail();
        $this->expectExceptionObject(new IdentityException('identity_projection_handoff_required', 409));
        $this->graph()->make(ProjectionOwnership::class)->transfer($owner->id, $owner->writer_binding, $owner->epoch);
    }

    public function test_two_model_classes_cannot_share_a_physical_native_row_without_an_approved_group(): void
    {
        app(UserSnapshotRepository::class)->apply($this->proof(1));
        $id = SharingUser::firstOrFail()->id;
        $this->configure(['identity.consumers.two.users.model' => SharingAliasUser::class, 'identity.consumers.two.sync.provision_missing' => false]);
        $this->selectConsumer('two');
        $wire = ['contract' => 'platform-consumer-sync-import.v1', 'issuer' => app(IdentityConfig::class)->issuer(), 'applicationId' => app(IdentityConfig::class)->applicationId(), 'clientId' => app(IdentityConfig::class)->clientId(), 'policyVersion' => 1, 'mappings' => [['sourceUserId' => 'source', 'subject' => 'person', 'version' => 2, 'state' => 'active', 'profile' => ProfileFixture::profile()]]];
        $result = UserImportResult::validate($wire, app(IdentityConfig::class), ['source']);
        $this->expectExceptionObject(new IdentityException('identity_native_sharing_denied', 409));
        app(UserImportBootstrap::class)->associate($result, [['sourceUserId' => 'source', 'nativeUserId' => $id]]);
    }

    public function test_shared_native_group_refuses_global_lifecycle_or_private_metadata_mapping(): void
    {
        $this->group();
        $this->expectException(IdentityException::class);
        $this->configure(['identity.consumers.one.users.fields.state' => 'active']);
    }

    public function test_older_target_proof_cannot_create_shared_association_after_revocation(): void
    {
        $this->group();
        $target = $this->proof(1);
        app(UserSnapshotRepository::class)->apply($target);
        $this->selectConsumer('two');
        app(UserSnapshotRepository::class)->apply($this->proof(1, 'Two'));
        $source = app(IdentityConfig::class)->bindingHash();
        $id = SharingUser::firstOrFail()->id;
        $this->selectConsumer('one');
        app(UserSnapshotRepository::class)->apply(UserSnapshot::validate(['subject' => 'person', 'version' => 2, 'state' => 'revoked', 'profile' => null], 1, app(IdentityConfig::class)));
        $this->expectExceptionObject(new IdentityException('identity_native_proof_invalid', 409));
        $this->graph()->make(NativeUserAssociation::class)->associate($target, $source, $id);
    }

    public static function acceptedProjectionStatuses(): array
    {
        return [[false], [true]];
    }

    #[DataProvider('acceptedProjectionStatuses')]
    public function test_association_requires_current_binding_policy_and_fresh_equal_revision_evidence(bool $pending): void
    {
        $this->group();
        $old = $this->proof(7);
        app(UserSnapshotRepository::class)->apply($old);
        $targetBinding = app(IdentityConfig::class)->bindingHash();
        $state = UserSyncState::where('binding_hash', $targetBinding)->where('subject', 'person')->firstOrFail();
        if ($pending) {
            // Existing accepted state after the additive migration: projection still awaits replay.
            $state->update(['native_status' => 'pending', 'native_version' => 0]);
        }
        $original = $state->only(['version', 'digest', 'profile', 'state']);
        $this->selectConsumer('two');
        app(UserSnapshotRepository::class)->apply($this->proof(3, 'Source'));
        $source = app(IdentityConfig::class)->bindingHash();
        $id = SharingUser::firstOrFail()->id;
        $this->selectConsumer('one');
        $repository = app(UserSnapshotRepository::class);
        $other = UserSnapshot::validate(['subject' => 'another-person', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()], 2, app(IdentityConfig::class));
        $repository->apply($other);
        $this->assertSame(2, UserSyncBinding::findOrFail($targetBinding)->policy_version);
        $this->assertSame(1, $state->refresh()->policy_version);
        $association = $this->graph()->make(NativeUserAssociation::class);
        try {
            $association->associate($old, $source, $id);
            $this->fail('Superseded policy proof created an association');
        } catch (IdentityException $error) {
            $this->assertSame('identity_native_proof_invalid', $error->errorCode);
        }
        $this->assertSame(0, IdentityUserLink::where('binding_hash', $targetBinding)->count());
        $this->assertSame(0, UserSyncRequest::where('binding_hash', $targetBinding)->count());
        $fresh = UserSnapshot::validate(['subject' => 'person', 'version' => 7, 'state' => 'active', 'profile' => $old->profile], 2, app(IdentityConfig::class));
        $this->assertSame($pending ? 'applied' : 'unchanged', $repository->apply($fresh));
        $this->assertSame(2, $state->refresh()->policy_version);
        $this->assertSame($original, $state->only(['version', 'digest', 'profile', 'state']));
        $this->assertSame(7, $state->native_version);
        $this->assertSame($id, $association->associate($fresh, $source, $id)->getAuthIdentifier());
        $this->assertSame('stale', $repository->apply($old));
        $this->assertSame($original, $state->refresh()->only(['version', 'digest', 'profile', 'state']));
        $this->assertSame(2, $state->policy_version);
        $conflict = UserSnapshot::validate(['subject' => 'person', 'version' => 7, 'state' => 'active', 'profile' => ProfileFixture::profile(['name' => 'Conflicting'])], 3, app(IdentityConfig::class));
        try {
            $repository->apply($conflict);
            $this->fail('Fresh policy bypassed equal-revision conflict');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_conflict', $error->errorCode);
        }
        $this->assertSame(2, $state->refresh()->policy_version);
        $this->assertSame($original, $state->only(['version', 'digest', 'profile', 'state']));
    }
}
