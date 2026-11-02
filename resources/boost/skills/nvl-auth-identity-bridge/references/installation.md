# Install and publish: nvl/auth-identity-bridge

Targets PHP 8.4+ and Laravel 13. This standalone Identity Platform consumer retains the `IdentityPlatform\Laravel` PHP namespace and requires neither `nvl/core` nor `nvl/auth`.

```sh
composer require nvl/auth-identity-bridge:^7.0
```

## Provider discovery

Composer package discovery registers these package-owned providers:

- `IdentityPlatform\Laravel\Providers\AuthIdentityBridgeServiceProvider`

The discovered wrapper keeps authentication disabled by default. It registers `IdentityPlatform\Laravel\IdentityServiceProvider` only when `nvl-auth-identity-bridge.enabled` is true. That opt-in provider owns the browser routes, middleware, import and reconciliation commands. Configure the trusted named consumers before enabling it.

Do not publish or copy vendor providers into the application. If discovery is deliberately disabled, register these exact classes in the application’s `bootstrap/providers.php`. Host policy and extension bindings belong in an application provider; see [usage](usage.md) for which bindings are required.

## Skills

Laravel Boost discovers this folder at `resources/boost/skills/` in the installed Composer package. In the consumer application, run:

```sh
php artisan boost:install --skills --no-interaction
```

Select skills through the installed Boost configuration when setting it up interactively. `php artisan boost:update --no-interaction` refreshes selected resources. Boost is a consumer development tool, not a required runtime dependency of this package. Agent Skills folders can also be copied to the skill directory supported by another agent; copy the entire folder so references and any scripts remain available.

The package also exposes its native Laravel publish group:

```sh
php artisan vendor:publish --tag=nvl-auth-identity-bridge-skills --no-interaction
```

That group copies the full skill tree to `.agents/skills`. Avoid force-overwriting application-authored changes; keep local conventions separate from vendor guidance.

## Publishable groups

- `identity-config`
- `nvl-auth-identity-bridge-config`
- `nvl-auth-identity-bridge-migrations`
- `nvl-auth-identity-bridge-skills`
- `nvl-auth-identity-bridge-views`

## Configuration

```sh
php artisan vendor:publish --tag=nvl-auth-identity-bridge-config --no-interaction
```

The group publishes both `config/nvl-auth-identity-bridge.php` (the disabled-by-default wrapper and migration switch) and `config/identity.php` (the connection, immutable named consumer definitions and service targets). Configure `identity.connection`, trusted consumers, native user mappings and supported shared locks before enabling the wrapper. Keep consumer bindings and credentials private; never store closures in cacheable configuration. Rebuild configuration caches and restart long-lived workers after reviewed changes.

## Migrations

Choose exactly one migration owner before the first migration:

- **Vendor-loaded:** enable the package migration loader and run ordinary `php artisan migrate --no-interaction` after reviewing storage and bindings.
- **Published:** publish the tagged files, disable `nvl-auth-identity-bridge.migrations.enabled` before migrating, then review and edit the application-owned copies before their first execution.

```sh
php artisan vendor:publish --tag=nvl-auth-identity-bridge-migrations --no-interaction
```

Publish migrations once during initial setup. Laravel retimestamps published migrations; publishing again can create duplicate dated copies even without `--force`. Update config or skills with their separate tags, and avoid a blanket `--provider` publication after migration setup. Do not run both vendor and host migration copies. Keep applied history intact; evolve an installed schema with a new reviewed host migration. Preserve required keys, unique constraints, indexes, ownership declarations and transaction connection.

Configure `identity.connection` before migration. The retained `identity_*` schema and migration names are fixed; this package exposes no table-remapping API. The vendor loader runs only while the wrapper is enabled and `nvl-auth-identity-bridge.migrations.enabled` is true. With host-published migrations keep vendor loading disabled. Review existing storage and native user mappings before admitting traffic; publication does not grant authorization.

## Artisan operations

These commands are registered by Composer-discovered package providers. Feature-gated commands require the corresponding enabled adapter/runtime. Read each installed command’s `--help` before supplying operation options:

- `php artisan nvl:auth-identity-bridge:doctor --help`
- `php artisan identity:users-import --help`
- `php artisan identity:users-reconcile --help`

## Verify the consumer

Use the package-specific checks in [usage](usage.md), verify required host bindings and run the affected consumer tests. Publishing files is not application or production certification. Preserve the documented explicit actor, revision, owner, locale and outer-commit requirements when adapting HTTP, CLI or jobs.

Official framework guidance: [Laravel package development](https://laravel.com/docs/13.x/packages) and [Boost third-party package skills](https://laravel.com/docs/13.x/boost#third-party-package-skills).
