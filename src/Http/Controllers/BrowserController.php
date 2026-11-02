<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Controllers;

use IdentityPlatform\Laravel\Auth\BrowserLifecycle;
use IdentityPlatform\Laravel\Support\ContextDefinition;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/** Default Blade/JSON adapter; custom framework adapters use the same public lifecycle. */
class BrowserController
{
    public function __construct(private BrowserLifecycle $browser, private IdentityConfig $config) {}

    public function entry(Request $request): View
    {
        return app('view')->make('identity::entry', ['identity' => $this->config]);
    }

    public function login(Request $request): JsonResponse|RedirectResponse
    {
        return $this->destination($request, $this->browser->startSignIn($request, $request->input('return_to', '/'), $request->boolean('resource')));
    }

    public function callback(Request $request): JsonResponse|RedirectResponse
    {
        return $this->destination($request, $this->browser->completeSignIn($request));
    }

    public function contexts(Request $request): JsonResponse|View
    {
        $contexts = $this->browser->discoverContexts($request);

        return $request->expectsJson() ? response()->json($contexts) : app('view')->make('identity::contexts', ['contexts' => ['contexts' => $contexts['contexts'], 'local_context_version' => $contexts['contextVersion']], 'identity' => $this->config]);
    }

    public function select(Request $request): JsonResponse|RedirectResponse
    {
        $destination = $this->browser->selectContext($request);

        return $request->expectsJson() ? response()->json(['destination' => $destination]) : redirect()->away($destination->url, 303);
    }

    public function logout(Request $request): JsonResponse|RedirectResponse
    {
        $this->browser->signOut($request);

        $prefix = $this->config->value('routes.path_prefix');
        ContextDefinition::require(is_string($prefix), 'browser_context_unavailable');

        return $this->destination($request, rtrim($prefix, '/').'/');
    }

    public function centralLogout(Request $request): JsonResponse|RedirectResponse
    {
        return $this->destination($request, $this->browser->centralSignOut($request));
    }

    public function signedOut(Request $request): JsonResponse|RedirectResponse
    {
        $this->browser->finishLogout($request);

        $prefix = $this->config->value('routes.path_prefix');
        ContextDefinition::require(is_string($prefix), 'browser_context_unavailable');

        return $this->destination($request, rtrim($prefix, '/').'/');
    }

    private function destination(Request $request, string $url): JsonResponse|RedirectResponse
    {
        return $request->expectsJson() ? response()->json(['redirect' => $url]) : redirect()->away($url, $request->isMethod('POST') ? 303 : 302);
    }
}
