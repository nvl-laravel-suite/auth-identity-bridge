<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Controllers;

use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager;
use IdentityPlatform\Laravel\Support\SafeReturn;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/** Headless discovery and ordinary POST commands; host adapters own their chooser UI. */
final class ApplicationContextController
{
    public function __construct(private ApplicationContextManager $contexts) {}

    public function index(Request $request): JsonResponse
    {
        $request->validate(['kind' => 'required|string|max:64']);

        return response()->json(['contexts' => $this->contexts->list($request, $request->string('kind')->toString())]);
    }

    public function current(Request $request): JsonResponse
    {
        return response()->json(['applicationContext' => $this->contexts->current($request)]);
    }

    public function select(Request $request): JsonResponse|RedirectResponse
    {
        $this->contexts->select($request);

        return $this->changed($request);
    }

    public function clear(Request $request): JsonResponse|RedirectResponse
    {
        $this->contexts->clear($request);

        return $this->changed($request);
    }

    private function changed(Request $request): JsonResponse|RedirectResponse
    {
        // Fetch fresh stable AuthState on the next read; never tag this write's old DTO with a newer version.
        $destination = SafeReturn::path($request->input('return_to', '/'));

        return $request->expectsJson() ? response()->json(['changed' => true, 'redirect' => $destination]) : redirect()->to($destination, 303);
    }
}
