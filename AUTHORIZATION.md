# Current decisions and Laravel abilities

Central application permission keys come from the request-bound `IdentityAccess` and the current selected application context. Native user fields, synchronized profiles, cached local permissions, assigned-role unions and platform-admin names never supply central authority. A central permission is necessary; the host still owns resource ownership, organization binding and business rules.

## Explicit checks

```php
use IdentityPlatform\Laravel\Authorization\IdentityAccess;

$access = app(IdentityAccess::class); // Selected by the browser consumer middleware.
$mayUpdate = $access->hasPermission('documents.update', fresh: true);
$isEditor = $access->hasSelectedRole('editor', fresh: true);
```

`hasSelectedRole` compares the one selected application role **key**, not a role ID or any role in the person's available role assignments. It returns false for roleless and delegated decisions; the delegated protocol supplies a selected role ID but no selected role key. `Principal::selectedRole()` makes the same distinction. The existing native `HasIdentityAccess` trait first binds its native owner before returning this helper. These explicit helpers can raise the existing `IdentityException` on missing, changed or unavailable authority; there is no local fallback.

Without `fresh: true`, the existing helper may use the still-valid bounded session decision. The named Gate integration and presenter below always request fresh ordinary authority. In delegated mode they use the existing short-lived, validated request decision produced by `DelegationBoundary`; they do not initiate a second delegation protocol.

## Opt in to named Gate abilities

Add this provider to the host's `bootstrap/providers.php`, before providers that retain Gate instances for later use:

```php
IdentityPlatform\Laravel\Authorization\IdentityAuthorizationServiceProvider::class,
```

Register code-owned families and mandatory business policy methods in a host provider's `boot` method:

```php
use App\Policies\DocumentPolicy;
use IdentityPlatform\Laravel\Authorization\AbilityRegistry;

public function boot(AbilityRegistry $abilities): void
{
    $abilities->family('documents.')
        ->map('documents.update', 'documents.update', DocumentPolicy::class, 'update');
}
```

The first string is the Laravel ability, the second is the central permission key. Families require a trailing `.` or `:` delimiter. Every name within an owned family is denied until explicitly mapped, even if `Gate::define` or a global admin callback otherwise allows it. Duplicate mappings and invalid, non-public, static, magic or before policy methods are rejected. Registration is trusted host code, never request input. A host can also bind an `AbilityRegistry` instance or container factory before this provider resolves it. Nothing is added to the cacheable Identity configuration and no new authority store exists.

The opt-in provider decorates Laravel's `Illuminate\Contracts\Auth\Access\Gate` service. The implementation inherits Laravel's check/any/authorize machinery and uses the existing Gate for unrelated abilities; it does not copy an authorization engine. For an owned ability it:

1. Requires a mapped name, a current request source and a native user matching the effective identity owner.
2. Fetches a fresh ordinary decision, or validates the existing delegated request decision, and requires its exact central permission key.
3. Resolves the configured host policy through the container and calls the configured method directly with the native user followed by the supplied arguments.
4. Accepts only strict `true` or an allowed Laravel `Response`; false, null, other truthy values and denied responses refuse. Denied response status/message are retained. An allow is refused if the decision expires while the resource rule runs.

Owned abilities deliberately do not run global Gate `before`/`after` callbacks or a policy's `before` method. This prevents both an earlier and a later local-admin callback from skipping central denial or the mandatory resource rule. Put every required local refusal in the mapped method itself. Normal `GateEvaluated` events are emitted after mapped business-policy evaluation; global callbacks remain normal for unrelated families. Registration methods, local policies and local denial responses continue through the existing Gate. A previously retained reference to the undecorated Gate cannot be replaced retroactively; install the provider during application bootstrap and resolve the Gate service afterward.

The required method receives **exactly** `$user, ...$arguments`. There is no implicit class-name removal, policy discovery or automatic `before` dispatch for owned names. Use explicit mapped methods, and pass the resource instance and any other method arguments. A policy for a create operation can accept just the user. Do not call the same mapped Gate ability recursively from its policy.

```php
public function update(User $user, Document $document): bool
{
    return (string) $document->user_id === (string) $user->getKey()
        && $document->organization_id === $this->identity->organizationId()
        && ! $document->is_final;
}
```

The named ability is now usable through the installed Laravel consumers:

```php
$user->can('documents.update', $document);
Gate::inspect('documents.update', $document);
Gate::authorize('documents.update', $document);
```

```blade
@can('documents.update', $document)
    <button type="submit">Save</button>
@endcan
```

Use the owned name `documents.update` consistently. An unrelated name such as Laravel's conventional `update` remains a host-local ability unless its own explicitly delimited family is registered. On-demand `Gate::allowIf`/`denyIf` have no named ability and are not central authorization helpers. `forUser($foreignUser)` and `$foreignUser->can(...)` cannot borrow the current person's authority. Background checks without a bound browser source deny, even when a native User object is supplied. No default consumer graph is selected on behalf of a job.

## Writes retain the existing runners

A presentation check, `@can`, Gate middleware, or a successful `Gate::authorize` before locking is insufficient to authorize a write. Keep the existing ordinary runner and place the mapped policy check **inside** its mutation callback, after the locked resource is obtained:

```php
return app(OrdinaryActionRunner::class)->run(
    $request,
    fn () => Document::query()->lockForUpdate()->findOrFail($id),
    function (Document $document) use ($command) {
        Gate::authorize('documents.update', $document);
        $document->update($command);
        return $document;
    },
);
```

Retain the request's context version, CSRF/Origin protections, the single consumer/domain connection, resource lock order and final source/context/generation/deadline fences. This feature does not alter either runner or provide a second transaction mechanism.

For delegated writes retain the existing operation registration, early `DelegationBoundary`, `DelegatedActionRunner`, resource/command admission, locked policy check, final fences and atomic audit/outbox. Call the mapped business policy inside that runner's mutation callback. The native user there is the effective subject; `IdentityAccess::actor()` remains the operator. A Gate allow is never delegation admission. Unregistered/pending/expired delegation remains denied.

## Safe frontend presentation

```php
use IdentityPlatform\Laravel\Authorization\CurrentDecisionPresenter;

$authorization = app(CurrentDecisionPresenter::class)->current()->toArray();
```

The immutable `CurrentDecisionView` also implements `JsonSerializable`. Its entire shape is:

```json
{
  "permissions": ["documents.update"],
  "selectedRole": "editor",
  "organizationId": null,
  "expiresAt": "2026-11-01T12:00:30Z",
  "contextVersion": 2
}
```

`selectedRole` is a role key, never an ID. Delegation exposes its existing effective permission list and `decisionValidUntil` as `expiresAt`, with null `selectedRole` because the protocol does not supply a key. It does not substitute the actor's role. No tokens, vault handles, subject/session identifiers, reasons, ledgers, assurance or decision internals are serialized.

The presenter resolves the currently selected graph each time `current()` is called, never caches a decision and never chooses a default graph. It can also be resolved from an explicitly selected, request-bound consumer graph. The local source, selected context, version and token generation are captured around principal resolution; the view uses that captured version, and a changed or disappeared source produces the empty view. Missing graph/session, invalid/revoked central responses or unavailable delegated authority likewise produce empty permissions and null for all other fields. Normal refresh/selection middleware remains responsible for browser state; this presenter is display data, not a second login/session implementation or server authorization proof. The frontend should discard it at expiry/context change; every server operation still checks current authority.

## Existing Spatie installations

No Spatie dependency or adapter is required. Keep the Identity-owned ability prefix distinct from local workflow permissions. Map that prefix as above and keep ownership/business constraints inside the mapped method. If a host business rule also uses a local Spatie permission, require that local result in addition to the central permission already enforced by this integration. A local result never replaces central allow.

Do not mirror central roles or permissions into Spatie authority tables, assign a local admin role from a profile or grant access from a stale local permission cache. Existing Spatie/global Gate callbacks continue handling unrelated local ability families; they cannot short-circuit the required central and resource checks for registered families.

## Verification boundary

`tests/Authorization/NamedAbilityTest.php` exercises the installed Laravel 13 Gate, native `User::can`, Blade `@can`, authorize/Response behavior, earlier/later global admin callbacks, owned unknown names, foreign/background refusals, selected-role changes, malformed/expired/revoked decisions, delegated actor/subject presentation and an ordinary transaction rollback after a context change. Existing `OrdinaryActionRunnerTest` covers source, selection, generation and deadline changes around resource locks.

These are isolated SQLite/Testbench tests with synthetic provider HTTP responses. They establish package composition behavior; they do not establish live provider, PostgreSQL contention, browser/Herd, production deployment or an entire release qualification.
