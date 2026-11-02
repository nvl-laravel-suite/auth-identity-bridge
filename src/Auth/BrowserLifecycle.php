<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\SafeReturn;
use Illuminate\Http\Request;

/** Public adapter boundary; protocol, state and fences remain with their established owners.
 * @api
 *
 * @phpstan-import-type ContextOption from \IdentityPlatform\Laravel\Authorization\AuthorizationClient
 */
final class BrowserLifecycle
{
    public function __construct(private SessionManager $sessions, private IdentityConfig $config, private PostContextDestinationResolver $destinations, private AuthStatePresenter $presenter, private BrowserCommand $commands) {}

    public function startSignIn(Request $request, mixed $returnPath = '/', bool $resource = false): string
    {
        $this->command($request);

        return $this->sessions->start($request, $returnPath, $resource);
    }

    public function completeSignIn(Request $request): string
    {
        return $this->sessions->complete($request, $request->query());
    }

    /** @return array{contexts: list<ContextOption>, contextVersion: int} */
    public function discoverContexts(Request $request): array
    {
        $result = $this->sessions->contexts($request);

        return ['contexts' => $result['contexts'], 'contextVersion' => $result['local_context_version']];
    }

    public function selectContext(Request $request): BrowserDestination
    {
        $this->command($request);
        $request->validate(['organizationId' => 'nullable|string|max:255', 'roleId' => 'nullable|string|max:255', 'context_version' => 'required|integer|min:1']);
        $selection = [];
        $organizationId = $request->input('organizationId');
        $roleId = $request->input('roleId');
        if (is_string($organizationId) && $organizationId !== '') {
            $selection['organizationId'] = $organizationId;
        }
        if (is_string($roleId) && $roleId !== '') {
            $selection['roleId'] = $roleId;
        }
        // Resolve before committing so a host resolver failure cannot turn a successful selection into a retry.
        $destination = $this->destinations->resolve($this->config->context(), SafeReturn::path($request->session()->get('identity.return_path', '/')));
        $this->sessions->select($request, $selection, $request->integer('context_version'));
        $request->session()->forget('identity.return_path');

        return $destination;
    }

    public function state(): AuthStateView
    {
        return $this->presenter->current();
    }

    public function signOut(Request $request): void
    {
        $this->command($request);
        $this->sessions->logout($request);
    }

    public function centralSignOut(Request $request): string
    {
        $this->command($request);

        return $this->sessions->logout($request, true);
    }

    public function finishLogout(Request $request): void
    {
        $query = CallbackInput::validate($request, $request->query());
        $this->sessions->finishLogout($request, $query['state'] ?? '');
    }

    private function command(Request $request): void
    {
        $this->commands->assert($request);
    }
}
