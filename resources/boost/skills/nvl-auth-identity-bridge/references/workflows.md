# Bridge integration recipes

Read the current installed package contracts named in SKILL.md before adopting a recipe. These are existing capabilities, not a request to build extra adapters.

## Browser login, redirects and logout

Use `Facades\Identity::browser()` on a request admitted by the package browser middleware. Render `state()` for actor/effective subject/decision/context presentation. Start login through a CSRF-protected POST calling `startSignIn($request, $safeLocalReturnPath)`; navigate the returned URL as a full browser navigation. Let the verified callback, context discovery and `selectContext($request)` own the transition. Selection submits the displayed `context_version` and returns a `BrowserDestination`.

Use `PostContextDestinationResolver` for a business landing decision and `BrowserDestination::local` or `::surface` for approved destinations, following HEADLESS-LIFECYCLE.md. A registered surface starts its own OIDC/session flow; never transfer a source cookie/token or accept an arbitrary external `return_to`. Use `signOut($request)` for local logout or `centralSignOut($request)` for the user's explicit central logout choice; keep the verified logout callback. Do not substitute native `Auth::login`, `attempt` or logout-only code on the identity guard.

## Read data and distinguish write paths

Select the consumer on the server, never from an unrestricted query parameter:

```php
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Facades\Identity;

$graph = Identity::consumer('workspace', $request);
$client = $graph->make(ConsumerClient::class);
$self = $client->call($request, 'profile.read');
```

`ConsumerClient::call` also owns the existing allowlisted `profile.update`, directory, access, roles/options, invitations and step-up operations. Read its current operation contract: their payloads and legacy array results differ from typed governed target commands. Do not invent endpoint names or send generic arbitrary HTTP. Provider field/security policy and client capabilities still apply to self-service changes. Host business-only attributes remain host-owned.

For authorized administration of another target, use `readProfile`/`readMetadata`, then submit only actual changes allowed by the current `writableFields` hint. The hint is display information, not a grant. Supply the displayed local context version in request input or `X-Identity-Context-Version`; it differs from the target's profile revision:

```php
$result = $client->updateProfile($request, [
    'userId' => $targetId,
    'expectedVersion' => $targetVersion,
    'changes' => $validatedChanges,
    'reason' => $auditReason,
    'idempotencyKey' => $originalCommandKey,
]);
// Retain $result->reference in private host draft/session storage.
// Present safe status/receipt/context/refresh/error fields under an opaque host draft ID.
```

The host validates/retains its form input. The provider decides current actor/client/target eligibility, field policy and recent MFA. Metadata uses `updateMetadata` and only `adminNotes`/`tags`; metadata manage also requires receiving-client `users.sync` and `users.sync.metadata` capabilities. Configure each group's explicit read/write field policy and global-effects acknowledgement; a writable hint alone does not establish setup eligibility. Omission preserves; null clears only nullable fields. Do not include `context_version` inside the strict command input array.

## Command recovery and native convergence

- `failed`: recognized refusal or pre-send failure; show the safe error kind/code and retain host input.
- `unknown` or `pending`: retain the returned original reference and reconcile with `operationStatus($request, $originalReference)` under the original actor/session/context. No new-key replay and no assumption of rollback.
- `committed`: the original receipt is authoritative for the command. Check `context` and `refresh` separately. A changed context or pending native refresh does not undo provider commit.

Governed reads and receipts never feed native mapping. Enable/configure the existing `users.sync` capability and mapping for authorized versioned snapshots. The managed owner requests that refresh after a confirmed write. For a host-triggered refresh use the explicit graph's `Sync\UserSyncManager::request($subject)`; its existing work repository/job handles durable, after-commit dispatch. Resume/reconcile through documented commands and persisted references rather than copying fields from a UI response or adding observers that echo every native save back to Identity. Signed events schedule invalidation/refetch, not authoritative field replacement. Keep independent field ownership and binding isolation.

For existing-user bootstrap, read IMPORTING.md: pause both `sync.provision_missing` and JIT creation via `ExistingNativeOnlyLifecycle`, drain/reload affected workers, register a trusted `UserImportSource`, then dry-run/import/resume the same run and reconcile. Preserve supplied native IDs/foreign keys. Cut over only after source exhaustion and unresolved import/native work are zero.

## Local operations and scoped impersonation

Register the owned ability family and keep native policies responsible for resource ownership and state. Use the chosen graph's `IdentityAccess` for live central decisions. Run ordinary local mutations inside `OrdinaryActionRunner`, with a database lock and native policy inside the mutation callback. A pre-render `@can`/Gate allow is insufficient for persistence.

Impersonation uses the existing delegation options/start/redeem/check/stop lifecycle, configured route and operation registries, early `DelegationBoundary` and `DelegatedActionRunner`. Keep the operator as actor and the impersonated person as effective subject; use the subject in native resource policy and record both in audit. Keep operation/resource/command admission, original idempotency key, locked policy, final live/context/token/delegation fences, atomic audit/outbox and after-commit effects. Delegated mode cannot use ordinary profile administration or other control-plane APIs. Never replace impersonation with `Auth::loginUsingId` or actor-token forwarding.

Application context remembers a host resource filter only. Register its trusted provider and recheck resource access; it changes neither central role nor effective identity. Machine callers use separately configured service targets and scopes with fixed HTTPS origins, no redirect/replay fallback and generation-safe token eviction. A worker cannot borrow browser authority through a native User object or default consumer.
