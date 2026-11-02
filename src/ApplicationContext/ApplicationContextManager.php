<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\ApplicationContext;

use Carbon\CarbonImmutable;
use IdentityPlatform\Laravel\Auth\BrowserCommand;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Http\Request;

/** Context is a bounded resource filter. The existing action runners/policies own writes.
 * @api
 */
final class ApplicationContextManager
{
    public function __construct(private SessionManager $sessions, private SessionRepository $rows, private OverlayRepository $overlays, private IdentityConfig $config, private ApplicationContextRegistry $registry, private ConsumerGraph $graph, private BrowserCommand $commands) {}

    /** @return list<ApplicationContextDescriptor> */
    public function list(Request $request, string $kind): array
    {
        $row = $this->ordinary($request);
        $result = [];
        foreach ($this->provider($kind)->choices(ApplicationContextScope::from($this->config, $row)) as $resource) {
            if (! $resource instanceof ApplicationContextResource || count($result) >= 100) {
                throw new IdentityException('application_context_invalid', 422);
            }
            $result[] = $this->descriptor($kind, $resource, $row);
        }
        $this->fence($request, $row);

        return $result;
    }

    public function select(Request $request): ApplicationContextDescriptor
    {
        $this->commands->assert($request);
        $data = $request->validate(['kind' => 'required|string|max:64', 'resourceId' => 'required|string|max:255']);
        $row = $this->ordinary($request);
        $this->version($request, $row);
        $provider = $this->provider($data['kind']);

        return $row->getConnection()->transaction(function () use ($request, $data, $row, $provider): ApplicationContextDescriptor {
            // Host membership locks precede the native source fence, like ordinary resource writes.
            $scope = ApplicationContextScope::from($this->config, $row);
            $resource = $provider->resolve($scope, $data['resourceId'], true);
            if (! $resource || $resource->resourceId !== $data['resourceId']) {
                throw new IdentityException('application_context_unavailable', 403);
            }
            $descriptor = $this->descriptor($data['kind'], $resource, $row);
            $this->fence($request, $row, true);
            if (! $descriptor->expiresAt->isFuture()) {
                throw new IdentityException('application_context_unavailable', 403);
            }
            $this->publish($row, ['descriptor' => $descriptor->jsonSerialize(), 'scope' => (array) $scope]);

            return $descriptor;
        });
    }

    public function clear(Request $request): void
    {
        $this->commands->assert($request);
        $row = $this->ordinary($request);
        $this->version($request, $row);
        $row->getConnection()->transaction(function () use ($request, $row): void {
            $this->fence($request, $row, true);
            $this->publish($row, null);
        });
    }

    public function current(Request $request): ?ApplicationContextDescriptor
    {
        $row = $this->sessions->current($request);
        if (! $row || $this->overlays->find($row->id)) {
            return null;
        }
        $descriptor = $this->forSource($row);
        // A failed revalidation clears/bump atomically; don't return an earlier descriptor.
        if ($descriptor) {
            $this->fence($request, $row);
        }

        return $descriptor;
    }

    /** Presenter seam: caller must compare its captured source/mode/version after this call. */
    public function forSource(IdentitySession $row): ?ApplicationContextDescriptor
    {
        if ($row->application_context === null || $this->overlays->find($row->id)) {
            return null;
        }
        $descriptor = $this->validated($row, false);
        if (! $descriptor) {
            // Compare-and-swap never clears a newer choice; no optional listener is involved.
            if (! $this->rows->publish($row, ['application_context' => null, 'context_version' => $row->context_version + 1])) {
                throw new IdentityException('context_changed', 409);
            }
        }

        return $descriptor;
    }

    /**
     * Call inside OrdinaryActionRunner's mutation, after host resource/membership locks.
     * The supplied principal is the runner's fresh ordinary proof. Still apply domain policy.
     * No transaction or authority cache is created here; a refusal rolls back that write.
     */
    public function assertEligible(Request $request, Principal $principal): ApplicationContextDescriptor
    {
        $id = $request->hasSession() ? $request->session()->get('identity.session') : null;
        $row = is_string($id) ? $this->rows->find($id) : null;
        if (! $row || $row->getConnection()->transactionLevel() < 1) {
            throw new IdentityException('application_context_fence_required', 409);
        }
        $this->version($request, $row);
        $this->requireOrdinary($row);
        $proof = $principal->decision;
        if (! array_key_exists('delegation', $proof) || $proof['delegation'] !== null || ($proof['subject'] ?? null) !== $row->subject || ($proof['central_session_id'] ?? null) !== $row->sid
            || ($proof['issuer'] ?? null) !== $this->config->issuer() || ($proof['application_id'] ?? null) !== $this->config->applicationId() || ($proof['client_id'] ?? null) !== $this->config->clientId()
            || ($proof['organization_id'] ?? null) !== ($row->selection['organizationId'] ?? null) || ($proof['selected_role_id'] ?? null) !== ($row->selection['roleId'] ?? null)
            || (Contract::date($proof['expires_at'] ?? null) ?? 0) <= microtime(true)) {
            throw new IdentityException('ordinary_authority_expired', 409);
        }
        $descriptor = $this->validated($row, true) ?? throw new IdentityException('application_context_unavailable', 403);
        $this->fence($request, $row, true);
        if (! $descriptor->expiresAt->isFuture()) {
            throw new IdentityException('application_context_unavailable', 403);
        }

        return $descriptor;
    }

    private function validated(IdentitySession $row, bool $lock): ?ApplicationContextDescriptor
    {
        $stored = $row->application_context;
        $scope = ApplicationContextScope::from($this->config, $row);
        if (! is_array($stored) || ($stored['scope'] ?? null) !== (array) $scope) {
            return null;
        }
        $data = $stored['descriptor'] ?? null;
        if (! is_array($data) || ! is_string($data['kind'] ?? null) || ! is_string($data['resourceId'] ?? null) || ! is_string($data['version'] ?? null)
            || ($data['consumerBinding'] ?? null) !== $scope->bindingHash || ($data['actorSubject'] ?? null) !== $scope->actorSubject || ($data['providerSelection'] ?? null) !== $this->selection($row)
            || (Contract::date($data['expiresAt'] ?? null) ?? 0) <= (float) now()->format('U.u')) {
            return null;
        }
        try {
            $resource = $this->provider($data['kind'])->resolve($scope, $data['resourceId'], $lock);
        } catch (IdentityException $error) {
            if (in_array($error->errorCode, ['application_context_unknown', 'application_context_unavailable'], true)) {
                return null;
            }
            throw $error;
        }
        if (! $resource || $resource->resourceId !== $data['resourceId'] || $resource->localVersion !== $data['version'] || ! $resource->expiresAt->isFuture()) {
            return null;
        }
        $expiry = CarbonImmutable::parse($data['expiresAt'])->min($resource->expiresAt);

        return $expiry->isFuture() ? $this->view($data['kind'], $resource, $row, $expiry) : null;
    }

    private function descriptor(string $kind, ApplicationContextResource $resource, IdentitySession $row): ApplicationContextDescriptor
    {
        $expiry = $resource->expiresAt->min(now()->addSeconds(300))->min($row->expires_at)->min($row->started_at->addSeconds((int) $this->config->value('local.absolute_seconds', 43200)));
        if (! $expiry->isFuture()) {
            throw new IdentityException('application_context_unavailable', 403);
        }

        return $this->view($kind, $resource, $row, $expiry);
    }

    private function view(string $kind, ApplicationContextResource $resource, IdentitySession $row, CarbonImmutable $expiry): ApplicationContextDescriptor
    {
        return new ApplicationContextDescriptor($kind, $resource->resourceId, $resource->label, $this->config->bindingHash(), $row->subject, $this->selection($row), $resource->localVersion, $expiry);
    }

    private function selection(IdentitySession $row): array
    {
        return ['organizationId' => $row->selection['organizationId'] ?? null, 'roleId' => $row->selection['roleId'] ?? null];
    }

    private function provider(string $kind): ApplicationContextProvider
    {
        return $this->graph->make($this->registry->provider($this->config->context()->name(), $kind));
    }

    private function ordinary(Request $request): IdentitySession
    {
        $row = $this->sessions->current($request) ?? throw new IdentityException('sign_in_required', 401);
        $this->requireOrdinary($row);

        return $row;
    }

    private function requireOrdinary(IdentitySession $row): void
    {
        if ($this->overlays->find($row->id)) {
            throw new IdentityException('ordinary_action_required', 403);
        }
        if (($row->selection['selected'] ?? false) !== true) {
            throw new IdentityException('context_required', 409);
        }
    }

    private function version(Request $request, IdentitySession $row): void
    {
        $version = $request->input('context_version', $request->header('X-Identity-Context-Version'));
        if (! is_scalar($version) || ! ctype_digit((string) $version) || (int) $version !== $row->context_version) {
            throw new IdentityException('context_changed', 409);
        }
    }

    private function fence(Request $request, IdentitySession $expected, bool $lock = false): void
    {
        $current = $this->rows->find($expected->id, $lock);
        $stamp = ['binding_hash', 'subject', 'sid', 'user_id', 'selection', 'context_version', 'token_generation', 'application_context'];
        if (! $current || ! $this->sessions->live($current) || ! $request->hasSession() || $request->session()->get('identity.session') !== $expected->id || $current->only($stamp) !== $expected->only($stamp)) {
            throw new IdentityException('context_changed', 409);
        }
        $this->requireOrdinary($current);
    }

    private function publish(IdentitySession $row, ?array $context): void
    {
        if (! $this->rows->publish($row, ['application_context' => $context, 'context_version' => $row->context_version + 1])) {
            throw new IdentityException('context_changed', 409);
        }
    }
}
