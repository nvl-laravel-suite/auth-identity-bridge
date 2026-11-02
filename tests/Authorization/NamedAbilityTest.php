<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Authorization;

use IdentityPlatform\Laravel\Authorization\AbilityRegistry;
use IdentityPlatform\Laravel\Authorization\CurrentDecisionPresenter;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Authorization\IdentityAuthorizationServiceProvider;
use IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Delegation\DelegationDecision;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\Access\Response;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

/** Interleave after real authority validation without replacing its effects. */
class InterleavedIdentityAccess extends IdentityAccess
{
    public \Closure $afterPrincipal;

    public function principal(bool $fresh = false): Principal
    {
        $principal = parent::principal($fresh);
        ($this->afterPrincipal)();

        return $principal;
    }
}

class AbilityUser extends User
{
    protected $table = 'ability_users';

    protected $guarded = [];
}

class AbilityDocument
{
    public function __construct(public int $owner, public bool $locked = false) {}
}

class AbilityDocumentPolicy
{
    public function before(AbilityUser $user): bool
    {
        return true;
    }

    public function update(AbilityUser $user, AbilityDocument $document): Response
    {
        return $user->id === $document->owner && ! $document->locked
            ? Response::allow() : Response::denyAsNotFound('Document unavailable.');
    }

    public function slow(AbilityUser $user, AbilityDocument $document): bool
    {
        usleep(1_100_000);

        return true;
    }

    public function invalid(AbilityUser $user, AbilityDocument $document): string
    {
        return 'truthy-is-not-allow';
    }
}

final class NamedAbilityTest extends TestCase
{
    private Request $request;

    private AbilityUser $owner;

    private array $decision;

    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('ability_users', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->boolean('local_admin')->default(true);
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.users.model' => AbilityUser::class, 'identity.consumers.one.users.fields' => ['name' => 'name']]);
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'ability-person', 'name' => 'Person']);
        $this->owner = app(IdentityUserResolver::class)->resolve($projection);
        app(SessionRepository::class)->create(['id' => 'ability-ledger', 'user_id' => $projection->id, 'subject' => 'ability-person', 'sid' => 'ability-source',
            'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:ability-ledger'),
            'selection' => ['selected' => true, 'roleId' => 'editor-id'], 'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->request = Request::create('https://consumer.test/documents', 'GET');
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', 'ability-ledger');
        $this->request->setLaravelSession($store);
        $this->bindRequest($this->request);
        Auth::setUser($this->owner);
        $this->decision = ['contract' => 'platform-authorization-snapshot.v1', 'issuer' => 'https://identity.test/api/auth', 'subject' => 'ability-person',
            'central_session_id' => 'ability-source', 'application_id' => 'app-1', 'client_id' => 'web-1', 'principal_kind' => 'user', 'session_status' => 'active',
            'security_version' => 1, 'identity_status' => 'active', 'application_status' => 'active', 'grant_status' => 'active', 'organization_id' => null,
            'selected_role_id' => 'editor-id', 'client_policy_version' => 1, 'role_ids' => ['editor-id'], 'roles' => ['editor'], 'permissions' => ['documents.update'],
            'authz_version' => 1, 'application_policy_version' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59),
            'assurance' => null, 'delegation' => null];
        Http::preventStrayRequests();
        Http::fake(fn () => Http::response($this->decision));
    }

    private function integrate(): void
    {
        self::assertTrue(class_exists(IdentityAuthorizationServiceProvider::class), 'Opt-in current-decision Gate integration is missing');
        $this->app->register(IdentityAuthorizationServiceProvider::class);
        app(AbilityRegistry::class)->family('documents.')->map('documents.update', 'documents.update', AbilityDocumentPolicy::class, 'update');
    }

    public function test_global_admin_callbacks_before_and_after_installation_cannot_bypass_current_revocation_or_resource_policy(): void
    {
        Gate::before(fn (AbilityUser $user) => $user->local_admin ? true : null);
        $this->integrate();
        Gate::before(fn (AbilityUser $user) => $user->local_admin ? true : null);
        self::assertTrue($this->owner->can('documents.update', new AbilityDocument($this->owner->id)));
        self::assertFalse($this->owner->can('documents.update', new AbilityDocument(999)));
        $this->decision['permissions'] = [];
        self::assertFalse($this->owner->can('documents.update', new AbilityDocument($this->owner->id)));
        Gate::define('documents.unregistered', fn () => true);
        self::assertFalse(Gate::allows('documents.unregistered', new AbilityDocument($this->owner->id)));
        self::assertTrue(Gate::allows('local.dashboard'));
    }

    public function test_gate_blade_authorize_and_response_preserve_required_business_denial(): void
    {
        $this->integrate();
        $document = new AbilityDocument($this->owner->id, true);
        self::assertSame(404, Gate::inspect('documents.update', $document)->status());
        self::assertSame('hidden', trim(Blade::render("@can('documents.update', \$document)\nvisible\n@else\nhidden\n@endcan", ['document' => $document], deleteCachedView: true)));
        $this->expectException(AuthorizationException::class);
        Gate::authorize('documents.update', $document);
    }

    public function test_unrelated_local_gate_policy_and_denial_keep_host_behavior(): void
    {
        $this->integrate();
        Gate::define('local.no', fn () => false);
        Gate::policy(AbilityDocument::class, AbilityDocumentPolicy::class);
        self::assertFalse(Gate::allows('local.no'));
        self::assertTrue(Gate::allows('update', new AbilityDocument(999))); // Host policy before remains local.
        app(AbilityRegistry::class)->map('documents.invalid', 'documents.update', AbilityDocumentPolicy::class, 'invalid');
        self::assertFalse(Gate::allows('documents.invalid', new AbilityDocument($this->owner->id)));
    }

    public function test_foreign_user_and_background_without_request_source_cannot_borrow_authority(): void
    {
        $this->integrate();
        Gate::before(fn () => true);
        $foreign = AbilityUser::query()->create(['name' => 'Other']);
        self::assertFalse($foreign->can('documents.update', new AbilityDocument($foreign->id)));
        self::assertFalse(Gate::forUser(null)->allows('documents.update', new AbilityDocument($this->owner->id)));
        $this->request->session()->forget('identity.session');
        self::assertFalse($this->owner->can('documents.update', new AbilityDocument($this->owner->id)));
        $this->app->forgetInstance(ConsumerGraph::class);
        self::assertSame([], app(CurrentDecisionPresenter::class)->current()->permissions);
        self::assertFalse(Gate::allows('documents.update', new AbilityDocument($this->owner->id)));
    }

    #[DataProvider('invalidDecisions')]
    public function test_expired_malformed_or_absent_decision_refuses_gate_and_safe_presentation(string $field, mixed $value): void
    {
        $this->integrate();
        $this->decision[$field] = $value;
        self::assertFalse(Gate::allows('documents.update', new AbilityDocument($this->owner->id)));
        self::assertSame(['permissions' => [], 'selectedRole' => null, 'organizationId' => null, 'expiresAt' => null, 'contextVersion' => null], app(CurrentDecisionPresenter::class)->current()->toArray());
    }

    public static function invalidDecisions(): array
    {
        return [['expires_at', '1999-01-01T00:00:00Z'], ['permissions', 'documents.update'], ['contract', null], ['roles', ['editor', 'admin']], ['selected_role_id', null], ['grant_status', 'denied']];
    }

    public function test_selected_role_and_frontend_view_follow_current_selection_without_exposing_authority_internals(): void
    {
        $this->integrate();
        self::assertTrue(app(IdentityAccess::class)->hasSelectedRole('editor', true));
        $view = app(CurrentDecisionPresenter::class)->current()->toArray();
        self::assertSame(['permissions', 'selectedRole', 'organizationId', 'expiresAt', 'contextVersion'], array_keys($view));
        self::assertSame(['documents.update'], $view['permissions']);
        self::assertSame('editor', $view['selectedRole']);
        self::assertSame(2, $view['contextVersion']);
        IdentitySession::query()->whereKey('ability-ledger')->update(['selection' => ['selected' => true, 'roleId' => 'reader-id'], 'context_version' => 3]);
        $this->decision = [...$this->decision, 'selected_role_id' => 'reader-id', 'role_ids' => ['reader-id'], 'roles' => ['reader'], 'permissions' => []];
        self::assertFalse(app(IdentityAccess::class)->hasSelectedRole('editor', true));
        self::assertTrue(app(IdentityAccess::class)->hasSelectedRole('reader', true));
        self::assertSame('reader', app(CurrentDecisionPresenter::class)->current()->toArray()['selectedRole']);
        self::assertFalse(Gate::allows('documents.update', new AbilityDocument($this->owner->id)));
    }

    #[DataProvider('presentationInterleavings')]
    public function test_presenter_never_pairs_old_authority_with_changed_or_missing_source(string $change): void
    {
        $access = $this->graph()->make(InterleavedIdentityAccess::class);
        $access->afterPrincipal = function () use ($change): void {
            $row = IdentitySession::query()->findOrFail('ability-ledger');
            match ($change) {
                'role' => $row->update(['selection' => ['selected' => true, 'roleId' => 'reader-id'], 'context_version' => 3]),
                'source' => $row->update(['sid' => 'replacement-source']),
                'missing' => $row->delete(),
            };
        };
        $this->graph()->instance(IdentityAccess::class, $access);

        self::assertSame(['permissions' => [], 'selectedRole' => null, 'organizationId' => null, 'expiresAt' => null, 'contextVersion' => null], app(CurrentDecisionPresenter::class)->current()->toArray());
    }

    public static function presentationInterleavings(): array
    {
        return [['role'], ['source'], ['missing']];
    }

    public function test_decision_expiring_during_business_policy_cannot_return_an_allow(): void
    {
        $this->integrate();
        app(AbilityRegistry::class)->map('documents.slow', 'documents.update', AbilityDocumentPolicy::class, 'slow');
        $this->decision['expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + 1);
        self::assertFalse(Gate::allows('documents.slow', new AbilityDocument($this->owner->id)));
    }

    public function test_local_denial_response_configuration_survives_wrapping(): void
    {
        Gate::defaultDenialResponse(Response::denyAsNotFound());
        Gate::define('local.no', fn () => false);
        $this->integrate();
        self::assertSame(404, Gate::inspect('local.no')->status());
        Gate::defaultDenialResponse(Response::denyWithStatus(409));
        self::assertSame(409, Gate::inspect('local.no')->status());
    }

    public function test_registration_refuses_unowned_abilities_and_duplicate_overrides(): void
    {
        $this->integrate();
        foreach ([['local.open', 'documents.update', 'update'], ['documents.other', 'not a permission', 'update'], ['documents.before', 'documents.update', 'before'], ['documents.update', 'documents.update', 'update']] as [$ability, $permission, $method]) {
            try {
                app(AbilityRegistry::class)->map($ability, $permission, AbilityDocumentPolicy::class, $method);
                self::fail('Unsafe ability registration accepted');
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_delegated_view_and_gate_use_effective_subject_without_admitting_a_write(): void
    {
        $this->integrate();
        $subject = app(UserSynchronizer::class)->sync(['sub' => 'delegated-person', 'name' => 'Subject', 'email' => 'subject@example.test']);
        $subjectUser = app(IdentityUserResolver::class)->resolve($subject);
        $data = ['contract' => 'platform-consumer-delegation.v1', 'issuer' => 'https://identity.test/api/auth', 'delegationId' => 'mode-1',
            'actor' => ['id' => 'ability-person', 'name' => 'Person', 'email' => 'actor@example.test', 'sourceSessionId' => 'ability-source', 'assurance' => ['centralSessionId' => 'ability-source', 'verifiedAt' => gmdate('Y-m-d\TH:i:s\Z')]],
            'subject' => ['id' => 'delegated-person', 'name' => 'Subject', 'email' => 'subject@example.test', 'locale' => 'en', 'classification' => 'person', 'assurance' => null],
            'applicationId' => 'app-1', 'clientId' => 'web-1', 'organizationId' => null, 'roleId' => 'subject-role-id', 'actorRoleId' => 'editor-id', 'contextVersion' => 2,
            'operations' => ['documents.update'], 'permissions' => ['documents.update'], 'versions' => ['authority' => 1], 'reason' => 'Synthetic support case', 'ticketReference' => 'CASE-1',
            'startedAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 1), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 300), 'checkedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'decisionValidUntil' => gmdate('Y-m-d\TH:i:s\Z', time() + 4)];
        $overlay = app(OverlayRepository::class)->save('ability-ledger', ['source_sid' => 'ability-source', 'context_version' => 2, 'status' => 'active', 'decision' => $data, 'expires_at' => now()->addMinutes(5), 'browser_binding' => 'synthetic-binding']);
        $this->request->attributes->set('identity.delegation', DelegationDecision::validate($data, IdentitySession::query()->findOrFail('ability-ledger'), $overlay, app(IdentityConfig::class)));
        self::assertTrue($subjectUser->can('documents.update', new AbilityDocument($subjectUser->id)));
        self::assertFalse($this->owner->can('documents.update', new AbilityDocument($this->owner->id)));
        $view = app(CurrentDecisionPresenter::class)->current()->toArray();
        self::assertSame(['documents.update'], $view['permissions']);
        self::assertNull($view['selectedRole']); // The delegated protocol has an ID, not a role key.
        self::assertSame($data['decisionValidUntil'], $view['expiresAt']);
        self::assertFalse($this->request->attributes->has('identity.delegation.admitted'));
        $this->request->attributes->remove('identity.delegation');
        self::assertFalse($subjectUser->can('documents.update', new AbilityDocument($subjectUser->id)));
        self::assertSame([], app(CurrentDecisionPresenter::class)->current()->permissions);
    }

    public function test_policy_runs_inside_existing_write_fence_and_context_change_rolls_back(): void
    {
        $this->integrate();
        $this->request->setMethod('POST');
        $this->request->merge(['context_version' => 2]);
        try {
            app(OrdinaryActionRunner::class)->run($this->request, fn () => $this->owner->newQuery()->lockForUpdate()->findOrFail($this->owner->id), function ($locked): void {
                Gate::authorize('documents.update', new AbilityDocument($locked->id));
                $locked->update(['name' => 'Should roll back']);
                IdentitySession::query()->whereKey('ability-ledger')->increment('context_version');
            });
            self::fail('Changed write context committed');
        } catch (IdentityException $error) {
            self::assertSame('context_changed', $error->errorCode);
        }
        self::assertSame('Person', $this->owner->refresh()->name);
    }
}
