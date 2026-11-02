<?php

declare(strict_types=1);

use IdentityPlatform\Laravel\Http\Controllers\ApplicationContextController;
use IdentityPlatform\Laravel\Http\Controllers\BrowserController;
use IdentityPlatform\Laravel\Http\Controllers\CallbackController;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\ConsumerRouteCollection;
use Illuminate\Support\Facades\Route;

$registry = app(ConsumerRegistry::class);
foreach ($registry->names() as $name) {
    $context = $registry->get($name);
    if (! $context->hasBrowser() || ! $context->value('routes.enabled')) {
        continue;
    }
    $host = parse_url($context->appOrigin(), PHP_URL_HOST);
    $hostParameter = ConsumerRouteCollection::hostParameter($name);
    $domain = '{'.$hostParameter.'}';
    Route::domain($domain)->where([$hostParameter => preg_quote($host, '#')])->prefix(trim($context->value('routes.path_prefix'), '/'))->middleware(['web', 'identity.safety'])->group(function () use ($context, $name, $hostParameter, $host): void {
        foreach ([['get', '/auth/application-contexts', 'index', 'application-contexts'], ['get', '/auth/application-context', 'current', 'application-context.current'], ['post', '/auth/application-context', 'select', 'application-context.select'], ['post', '/auth/application-context/clear', 'clear', 'application-context.clear']] as [$method, $path, $handler, $action]) {
            Route::$method($path, [ApplicationContextController::class, $handler])->name($context->routeName($action))->defaults('identity_consumer', $name)->defaults($hostParameter, $host);
        }
        foreach ([['get', '/auth/entry', 'entry', 'entry'], ['post', '/auth/sign-in', 'login', 'login'], ['get', '/auth/callback', 'callback', 'callback'], ['get', '/auth/contexts', 'contexts', 'contexts'], ['post', '/auth/context', 'select', 'context.select'], ['post', '/auth/sign-out', 'logout', 'logout'], ['post', '/auth/central-sign-out', 'centralLogout', 'central-logout'], ['get', '/signed-out', 'signedOut', 'signed-out']] as [$method, $path, $handler, $action]) {
            Route::$method($path, [BrowserController::class, $handler])->name($context->routeName($action))->defaults('identity_consumer', $name)->defaults($hostParameter, $host);
        }
    });
    foreach ([['routes.backchannel_logout_uri', 'logout', 'backchannel-logout'], ['routes.event_uri', 'event', 'events']] as [$key, $handler, $action]) {
        Route::domain($domain)->where([$hostParameter => preg_quote($host, '#')])->post(parse_url($context->value($key), PHP_URL_PATH), [CallbackController::class, $handler])->name($context->routeName($action))->defaults('identity_consumer', $name)->defaults($hostParameter, $host)->defaults('identity_stateless', true);
    }
}
