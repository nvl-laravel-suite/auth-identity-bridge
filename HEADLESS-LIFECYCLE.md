# Headless browser lifecycle

The Laravel 13/PHP 8.4 package owns protocol verification and local identity sessions. A host may keep its Blade, JSON, Inertia or Livewire UI. The default `BrowserController` is an adapter over the same public services. No framework recipe adds a package runtime dependency.

## Select the trusted consumer

The early package middleware selects the registered HTTPS origin/path before session and controller construction. Within that HTTP request:

```php
use IdentityPlatform\Laravel\Facades\Identity;

$browser = Identity::browser();
```

This facade requires the selected request graph and its native session; it never falls back to a default consumer in a job. A trusted host integration can construct an explicit graph:

```php
$graph = Identity::consumer('staff', $request); // Name from server registration, not request data.
$browser = $graph->make(\IdentityPlatform\Laravel\Auth\BrowserLifecycle::class);
```

Keep custom browser routes in the normal `web`/`identity.safety` pipeline, with exact consumer route defaults and the early delegation boundary. Add an explicit allowed delegation operation only for a genuine delegated business route. A state endpoint does not admit a delegated mutation. Keep resource policies and existing ordinary/delegated action runners.

## Public lifecycle

| Method | Result |
| --- | --- |
| `startSignIn(Request, returnPath = '/', resource = false)` | Verified provider authorization URL; creates the existing one-use browser-bound intent and PKCE state. |
| `completeSignIn(Request)` | Local context-selection path after the verified code exchange and local session establishment. |
| `discoverContexts(Request)` | Allowlisted `{contexts, contextVersion}` for the provider choices. |
| `selectContext(Request)` | `BrowserDestination` after validating and committing the provider selection. |
| `state()` | `AuthStateView` containing safe actor/effective identity and finite display decision. |
| `signOut(Request)` | Retires local session and invalidates native session; best-effort provider revoke. |
| `centralSignOut(Request)` | The same local retirement followed by the provider's logout-confirmation URL. |
| `finishLogout(Request)` | Consumes the existing one-use, browser-bound logout continuation. |

Commands require POST, exact configured Origin and the native CSRF token in `_token` or `X-CSRF-TOKEN`. Keep Laravel CSRF middleware enabled. Context selection requires `context_version` and accepts nullable `organizationId`/`roleId`; the provider's current choices remain authoritative. These operations do not authorize arbitrary application writes.

Callbacks consume the actual request query. Shared `CallbackInput` validation rejects oversized raw queries, duplicate encoded OAuth keys and array-valued fields before consuming an intent. Do not flatten callback parameters in an adapter. The lower-level `SessionManager::complete` uses this validation too. Failed exchanges and replay never establish another local session. Logout works when the local identity session is already expired, and provider failure cannot resurrect local authority. Central continuation replay is refused by the existing intent owner.

The default controllers render Blade contexts for browser requests. JSON requests receive context data or `{redirect: url}`; selection returns `{destination: {kind, url, consumer}}`. Normal browser commands redirect with 303; callback redirects use 302. Expected identity errors retain sanitized `{error: code}`, HTTP status and no-store headers for both browser and JSON callers. Native validation retains Laravel's normal browser/JSON behavior. A JSON client must perform full browser navigation for an OIDC URL, not fetch the provider through XHR.

## Safe state

`AuthStateView::toArray()` and JSON serialization contain only:

- `consumer`: registered consumer name.
- `actor` and `effectiveSubject`: nullable `IdentityView` with `subject`, `name`, `email`, `picture`. Ordinary state shares the same identity; delegation retains the actor separately. A pending overlay has no effective subject or permissions.
- `contextVersion`: the local context fence version.
- `decision`: the exact `CurrentDecisionView` from `IdentityAccess`, containing `permissions`, `selectedRole`, `organizationId`, `expiresAt`, `contextVersion`.
- `delegation`: finite `status` and nullable `expiresAt`.
- `applicationContext`: nullable safe host descriptor; this lifecycle layer does not invent or persist host authority.

`decision.selectedRole` is the ordinary selected role **key**, never a role ID or role union. It is null for delegated decisions. Delegated permissions and decision expiry come from the effective finite provider decision. This DTO is presentation, never an authorization cache or write grant.

The presenter captures and rechecks source identity, selection, generation, context version, lifetime and delegation mode around profile/decision resolution. A moving or unusable source yields empty identity/permissions/version rather than combining different states. Ordinary display facts come from `UserProjectionRepository::find` for this binding; mutable common projection fields written by another consumer are not used. Delegated display facts are allowlisted from the currently validated finite subject decision. Native models, snapshots, security/governance fields, private notes, token bundles, vault references, source session IDs and internal ledgers are excluded.

## Destinations and another browser surface

Bind `PostContextDestinationResolver` to an application class in a service provider. The graph reconstructs that binding within its immutable consumer context; config remains cacheable. The resolver receives the source `ConsumerContext` and the source intent's bound return path. The default `LocalDestinationResolver` applies `SafeReturn::path` and preserves same-origin local paths. The destination is resolved before committing selection so resolver failure cannot repeat a committed selection.

```php
final class StaffDestination implements PostContextDestinationResolver
{
    public function __construct(private ConsumerRegistry $registry) {}

    public function resolve(ConsumerContext $consumer, string $returnPath): BrowserDestination
    {
        // A trusted server policy chooses this registered target, never a request URL.
        return BrowserDestination::surface($this->registry, 'reports');
    }
}
// Host service provider:
$this->app->bind(PostContextDestinationResolver::class, StaffDestination::class);
```

`BrowserDestination` has a private constructor and factories for a safe local path or trusted registered consumer. A surface destination points to that consumer's registered `/auth/entry` path (including its path prefix/port). The target landing renders a form with the **target's** CSRF token; submitting it starts the target's independent OIDC flow and creates its own login intent/session/cookie. It forwards no source return path, identity credential, token, cookie or delegation. A registered resource-only or routes-disabled consumer is not a package browser destination. The target can enjoy central SSO without sharing local sessions. This is a two-step browser transition, not a transferred authentication grant. Live two-surface HTTPS/browser qualification is separate from package fixture evidence.

## Lifecycle notifications

The package emits immutable purpose-specific DTOs:

| Event | Safe fields |
| --- | --- |
| `AuthenticatedSessionEstablished` | consumer, actorSubject, contextVersion |
| `ContextSelected` | consumer, actorSubject, organizationId, roleId, contextVersion |
| `LocalSessionEnded` | consumer, actorSubject, contextVersion |
| `DelegationStateChanged` | consumer, actorSubject, effectiveSubject, status, contextVersion, expiresAt |

`ContextSelected.roleId` identifies the committed provider selection; frontend role-key checks use `state().decision.selectedRole`. Events contain no model, session/vault handle, token, credential hash, private reason/ticket or URL.

Events follow successful local state changes. Within an outer database transaction they are deferred until its outer commit; rollback discards them. The callback captures this graph's dispatcher and immutable event immediately, without an ambient/default graph lookup after commit. No authentication event follows failed login or replay; delegated checks do not emit another mode transition. The established session precedes context selection. Local ended notifications cover SessionManager retirement and LocalSessionDirectory revocation; bulk background synchronization and signed invalidation retain their existing specialized owners.

Notifications are best effort, in process, with no package retry/outbox or external delivery service. A throwing optional listener is swallowed at the dispatch boundary; Laravel may stop later listeners for that dispatch. The committed state and security cleanup still stand. A crash can lose a notification. Existing delegation queue restrictions also apply; installing a queued listener does not bypass them. A queued host listener owns its own idempotency/delivery handling and may retain only the safe event facts, never ambient browser credentials. Never retry a code exchange, selection or security transition to repair notification delivery. Core context cleanup and authorization invalidation must execute in the transition owner, not an optional listener. `ProfileSynchronized` stays a separate background-capable profile synchronization event and must not redirect a browser.

## Blade and JSON adapters

Blade uses normal POST navigation, native CSRF and escaped safe presentation:

```blade
<form method="post" action="{{ $identity->url('login') }}">
    @csrf
    <input type="hidden" name="return_to" value="/documents">
    <button type="submit">Sign in</button>
</form>
@if ($state->actor)
    <p>{{ $state->effectiveSubject?->name }}</p>
@endif
```

A host JSON state action can return `response()->json(Identity::browser()->state())`. On a permitted POST route the controller can return `response()->json(['redirect' => Identity::browser()->startSignIn($request, '/documents')])`; JavaScript sends the CSRF header and uses `window.location.assign(result.redirect)`. Do not persist these state/decision props into a cross-session cache. Context forms send the displayed local version, and stale forms receive 409 rather than silently switching authority.

## Inertia and Livewire recipes

These are integration recipes, not installed/tested framework adapters. Version scope is Inertia v2 and Livewire 3.x; check your installed version when adopting them.

Inertia: share `Identity::browser()->state()->toArray()` as presentation props on an admitted request. For a sign-in or central sign-out action return `Inertia::location($browser->startSignIn($request))` (or the logout URL). For a surface destination use `Inertia::location($destination->url)`. Inertia's external-location response performs full browser navigation; do not send the OIDC request through an Inertia page visit. See the official [Inertia v2 redirects guide](https://inertiajs.com/docs/v2/the-basics/redirects).

Livewire: the simplest integration is the normal Blade POST form above, without `wire:submit` interception. If using a Livewire action, pass the native CSRF token explicitly in the request input/header required by `BrowserLifecycle`; call `$this->redirect($url, navigate: false)` for the returned OIDC/surface URL. Keep callbacks as ordinary full-page package routes. Do not use `wire:navigate` or `navigate: true` for OIDC. Livewire performs redirects on the frontend through its redirect helper; see official [Livewire 3 redirecting](https://livewire.laravel.com/docs/3.x/redirecting) and [navigation](https://livewire.laravel.com/docs/3.x/navigate) guidance.

## Replacing native login/logout callers

Replace calls that manufacture an identity guard user (`Auth::login`, `loginUsingId`, remembered native-user restoration or password `attempt` on the identity guard) with `startSignIn` and the verified callback. Replace native logout-only calls with `signOut`, or `centralSignOut` when the user explicitly chooses central logout. Native password guards can remain separate ordinary application features; they do not create an Identity Platform session or grant central authority.

Native `Auth::user()` continues to resolve through the configured identity guard/native association for application policies. UI adapters should consume the safe `state()` DTO instead of serializing native users or reading guard/session internals. Background jobs select their explicit consumer and their own allowed service/sync plane; they do not use browser lifecycle APIs as ambient authority.
