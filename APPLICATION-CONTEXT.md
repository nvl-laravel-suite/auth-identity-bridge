# Application resource context

An application context is a remembered resource filter, such as a document workspace or support case. It is separate from the provider organization/role selection and separate from scoped delegation. It grants no permissions, changes no effective identity, and does not replace a resource policy. Hosts without registered providers retain their existing authentication behavior and receive `applicationContext: null` in `AuthStateView`.

## Register trusted providers

Register definitions in a host service provider's `boot()` method, before serving requests:

```php
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry;

public function boot(ApplicationContextRegistry $contexts): void
{
    $contexts->register('staff', 'workspace', WorkspaceContexts::class);
    $contexts->register('staff', 'case', SupportCaseContexts::class);
}
```

Each `(consumer, kind)` has one trusted provider class implementing `ApplicationContextProvider`. Duplicate or invalid registrations refuse. The shared registry contains only these definitions; it contains no request, session, provider instance, authority or model. Classes and their dependencies resolve inside the selected immutable consumer graph, including when the host container has already resolved a singleton. A browser cannot choose a PHP class. Keep a kind's meaning stable across deployments.

The interface is:

```php
public function choices(ApplicationContextScope $scope): iterable;
public function resolve(
    ApplicationContextScope $scope,
    string $resourceId,
    bool $forUpdate,
): ?ApplicationContextResource;
```

Return only eligible resources. `resolve` requeries current facts and returns null for a missing resource or membership. `choices` returns at most 100 currently eligible choices; filter or bound larger sets in your host adapter. Each resource has a string ID, plain-text safe label, string `localVersion`, and `CarbonImmutable` finite expiry. IDs, labels and versions must be nonempty, at most 255 bytes and contain no control characters. Escape labels in HTML. Never put credentials, private policy facts, Eloquent models or arbitrary payloads in these fields. `localVersion` must cover the relevant resource and membership revisions; a changed revision invalidates a remembered choice.

`ApplicationContextScope` contains the exact server-owned consumer binding, source row/SID, ordinary actor subject/native identity, and selected provider organization/role identity. The private source row/SID and native identity are persisted beside the descriptor and excluded from its public JSON. The public descriptor contains exactly `kind`, `resourceId`, `label`, `consumerBinding` (binding hash), `actorSubject`, `providerSelection` (nullable `organizationId`/`roleId` pair), `version` (the host resource’s localVersion) and UTC `expiresAt`. These safe binding facts cannot grant authority.

## Public API and browser adapters

Resolve `ApplicationContextManager` from the current selected graph, or explicitly use `Identity::consumer('staff', $request)->make(ApplicationContextManager::class)` in a trusted host adapter. No default consumer fallback is introduced.

- `list(Request, string $kind): array` returns safe eligible descriptors.
- `select(Request): ApplicationContextDescriptor` consumes `kind`, `resourceId` and expected `context_version` (or `X-Identity-Context-Version`). Any labels/policy fields supplied by a browser are ignored; only provider facts are saved.
- `current(Request): ?ApplicationContextDescriptor` revalidates current membership/resource facts.
- `clear(Request): void` clears the remembered choice.
- `assertEligible(Request, Principal): ApplicationContextDescriptor` is the ordinary write composition seam described below.

Select and clear require POST, exact configured `Origin`, and the native `_token` or `X-CSRF-TOKEN`; they share `BrowserCommand` with the public browser lifecycle. They require a live ordinary source and an explicitly selected provider context. Every successful select or clear advances the existing `context_version`, even when clearing an already-empty choice. A stale version refuses with `context_changed` (409). Unknown kind is 422; forged/missing/ineligible resource is 403. A delegated or pending source refuses ordinary context commands, including expired overlays awaiting the existing stop/retirement path.

Default routes, beneath the consumer's configured path prefix, are:

| Method | Path | Route action |
| --- | --- | --- |
| GET | `/auth/application-contexts?kind=workspace` | `application-contexts` |
| GET | `/auth/application-context` | `application-context.current` |
| POST | `/auth/application-context` | `application-context.select` |
| POST | `/auth/application-context/clear` | `application-context.clear` |

Read routes return allowlisted JSON. Commands return JSON `{ "changed": true, "redirect": "/" }` for JSON clients, or a 303 to a safe local `return_to` (default `/`). Fetch fresh `AuthStatePresenter::current()` on the next read to obtain the stable context version and descriptor together. Command responses do not combine a prior descriptor with a later version. Hosts own chooser UI; no sample domain tables or screens are installed by this feature.

The public state presenter composes context within its existing captured source/mode/version checks. If membership validation clears context, or the source changes while presentation is assembled, it returns the existing safe empty state. The following read can show the new ordinary state. `CurrentDecisionView` and central authorization semantics are unchanged.

## Lifetime and core transitions

A selection expires at the earliest of the host expiry, five minutes, or the original local session/absolute deadline. Reading it never extends this remembered lifetime. Current reads query the provider again and use its current safe label. Missing membership/resource, changed local revision, changed binding/actor/source/provider selection, or expiry clears the descriptor with a compare-and-swap and increments the existing context version. A concurrent newer selection is never cleared by a stale read. Provider failures do not become eligibility; errors propagate safely through existing boundaries.

A legitimate token refresh for the same actor/source/selection preserves the descriptor and its original expiry. Membership is still requeried before returning it. A changed native identity on refresh clears it and increments the context version. Provider context selection clears it in that same existing version transition. Signed provider invalidation clears it atomically beside snapshot invalidation and the existing version increment. New local sessions start empty; sign-out or replacement removes the old source and descriptor.

Delegation start clears context in the same transaction and version increment that creates the pending overlay. That exact version is used by the handoff and overlay, so clearing cannot make a newly-created delegation stale. Redeem inherits that empty context; stop clears again in its existing version increment and never restores an earlier choice. Clearing is core persistence behavior; optional event listeners are not involved.

## Host locks and ordinary writes

A provider is responsible for real eligibility queries and locking. `resolve(..., true)` runs inside the consumer transaction and must lock every host resource/membership fact whose change can revoke eligibility. Use the same consumer database connection and a documented consistent order. An unlocked cached membership lookup is insufficient. If membership deletion/changes do not honor those locks, the host cannot claim a write-time guarantee.

For a document-workspace implementation, a reasonable host order is workspace row, membership row, document row, then the package's native source fence. Query membership with the exact consumer binding, actor, selected organization/role and workspace ID. An eligible row returns `ApplicationContextResource($workspace->id, $workspace->name, "$workspace->version:$membership->version", $deadline)`. A second domain can implement the same interface with case-assignment rows and its own policy; the package has no workspace/case schema.

The existing runner still owns the transaction and current authority:

```php
return $ordinaryActions->run(
    $request,
    function () use ($documents, $workspaceId, $documentId) {
        // Host repository locks workspace, membership and document on the consumer connection.
        // Check all association keys; never lock a document solely because its ID was submitted.
        return $documents->lockWorkspaceMembershipAndDocument($workspaceId, $documentId);
    },
    function ($document, $principal) use ($contexts, $request, $documentPolicy, $documents, $validatedFields) {
        $context = $contexts->assertEligible($request, $principal);
        abort_unless($context->kind === 'workspace' && $context->resourceId === $document->workspace_id, 403);
        // Host policy checks the current central permission plus ownership/resource restrictions.
        $documentPolicy->assertUpdate($principal, $document);
        return $documents->updateLocked($document, $validatedFields);
    },
);
```

This is an integration recipe, not a new package repository API. Required host locks must already be held by the runner's `lockResource` callback before `assertEligible`; the provider's update query rechecks those locked facts. The assertion requires an existing transaction, matching expected source version, live ordinary mode and the runner's finite, exactly bound ordinary principal. It cannot grant `documents.update` or substitute for the policy. The runner rechecks its source fence before mutation and before commit. A context switch during a held write invalidates that write; membership refusal rolls back the transaction. A rolled-back assertion does not commit cleanup separately—its next current-state read clears the stale descriptor.

## Delegated support actions and other surfaces

The application context selector is ordinary-only. Do not register these package context routes as delegated operations. `DelegationBoundary` continues to deny unknown routes; a host cannot obtain delegated context selection merely by mapping one of those routes. The manager independently rejects overlays.

For an authorized support action, use the existing `DelegatedActionRunner` and sample `DocumentPolicy` pattern: explicitly register the admitted document operation, lock the owned document/workspace/membership facts in the host resource callback, and requery subject eligibility under those locks inside the established fenced mutation. Apply the resource policy to the centrally validated effective subject and operation. Preserve actor/subject audit, finite admission/deadlines, recent operator MFA and atomic mutation/audit/outbox. Do not reuse the operator's previous ordinary workspace as the subject's authority or add a second generic transaction runner. Application context is null in delegated state; host support workflow inputs remain resource identifiers validated by the existing delegated policy.

For another browser surface, first establish the operator's independent ordinary session in that target consumer using the public lifecycle/target entry flow. Then establish a separate delegation approved for that target client. Transfer neither an existing client-bound delegation nor an ordinary subject token between surfaces. Central operator authority, target-client policy, selected subject role and admitted operation remain required.

## Installation and evidence limits

`2026_11_01_000400_add_identity_application_context.php` adds one nullable JSON field to the package's existing session table. It changes no host schema or provider database. Apply it through the host's normal coordinated migration process; this implementation task did not apply it to an active store.

Isolated Testbench tests cover persisted host resource/membership fixtures, version/source fences, transitions, exact binding, finite descriptors, real signed synthetic OIDC refresh, default HTTP adapters and presenter redaction/coherence. SQLite interleavings do not prove cross-worker PostgreSQL row locking. Real PostgreSQL, HTTPS/browser multi-origin flows and the P11 sample UI/domain rollout remain separate qualification gates.
