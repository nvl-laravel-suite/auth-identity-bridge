<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Controllers;

use IdentityPlatform\Laravel\Auth\BrowserLifecycle;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Http\Request;

/** Default Blade/JSON adapter; custom framework adapters use the same public lifecycle. */
class BrowserController
{
    public function __construct(private BrowserLifecycle $browser, private IdentityConfig $config) {}

    public function entry(Request $request)
    {
        return view('identity::entry', ['identity' => $this->config]);
    }

    public function login(Request $request)
    {
        return $this->destination($request, $this->browser->startSignIn($request, $request->input('return_to', '/'), $request->boolean('resource')));
    }

    public function callback(Request $request)
    {
        return $this->destination($request, $this->browser->completeSignIn($request));
    }

    public function contexts(Request $request)
    {
        $contexts = $this->browser->discoverContexts($request);

        return $request->expectsJson() ? response()->json($contexts) : view('identity::contexts', ['contexts' => ['contexts' => $contexts['contexts'], 'local_context_version' => $contexts['contextVersion']], 'identity' => $this->config]);
    }

    public function select(Request $request)
    {
        $destination = $this->browser->selectContext($request);

        return $request->expectsJson() ? response()->json(['destination' => $destination]) : redirect()->away($destination->url, 303);
    }

    public function logout(Request $request)
    {
        $this->browser->signOut($request);

        return $this->destination($request, rtrim($this->config->value('routes.path_prefix'), '/').'/');
    }

    public function centralLogout(Request $request)
    {
        return $this->destination($request, $this->browser->centralSignOut($request));
    }

    public function signedOut(Request $request)
    {
        $this->browser->finishLogout($request);

        return $this->destination($request, rtrim($this->config->value('routes.path_prefix'), '/').'/');
    }

    private function destination(Request $request, string $url)
    {
        return $request->expectsJson() ? response()->json(['redirect' => $url]) : redirect()->away($url, $request->isMethod('POST') ? 303 : 302);
    }
}
