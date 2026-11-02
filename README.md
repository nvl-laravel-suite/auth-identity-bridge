# NVL Auth Identity Bridge

A standalone Laravel 13 / PHP 8.4+ consumer bridge for Identity Platform OIDC, browser sessions, host-owned native users, authorization, versioned synchronization, governed profile commands and named service targets. It requires neither `nvl/core` nor `nvl/auth`, a provider source checkout or access to the provider database.

The Composer package is `nvl/auth-identity-bridge`; the established PHP namespace remains `IdentityPlatform\Laravel`. The `identity` configuration, public method names, command names and provider wire contracts retain their existing forms. Shared profiles and native users carry facts; current provider decisions and host resource policies determine authority.

## Installation

```sh
composer require nvl/auth-identity-bridge:^7.0
php artisan vendor:publish --tag=nvl-auth-identity-bridge-config --no-interaction
```

Composer discovers `IdentityPlatform\Laravel\Providers\AuthIdentityBridgeServiceProvider`. The bridge defaults to disabled, so installation alone does not activate identity routes, guards or authentication middleware. Configure the published `config/identity.php` with the trusted issuer, application, named consumers, native model mapping, separately scoped credentials, shared lock store and session ownership. Secrets belong in the host's private environment or secret manager.

Choose the migration owner before the first run. To load the unchanged vendor migrations, enable `nvl-auth-identity-bridge.enabled` and leave `nvl-auth-identity-bridge.migrations.enabled` true. Alternatively, publish `nvl-auth-identity-bridge-migrations` once and set the migration flag false before running the application-owned copies. Review the intended `identity.connection` and native connection first; preserve migration filenames, applied history and existing data. Never run both sets of copies.

```sh
php artisan migrate --no-interaction
php artisan nvl:auth-identity-bridge:doctor --strict
```

The doctor validates local configuration without contacting the provider. A configured result does not qualify an OIDC registration, callback delivery, production cache or deployment. Follow the installed [installation reference](resources/boost/skills/nvl-auth-identity-bridge/references/installation.md) and [upgrade guide](UPGRADING.md) for publication and existing installations. The package uses a proprietary license; see [LICENSE](LICENSE).

## Integration contracts

| Capability | Contract |
| --- | --- |
| Browser login, redirects, context selection and logout | [Headless lifecycle](HEADLESS-LIFECYCLE.md) |
| Current authority, native policies and scoped impersonation | [Authorization](AUTHORIZATION.md) |
| Self-service data and reusable host adapters | [Integration contracts](docs/reusable-integration-contracts.md), [profile bootstrap](docs/profile-and-user-bootstrap.md) |
| Governed target updates and original-command recovery | [Consumer management](CONSUMER-MANAGEMENT.md) |
| Versioned provider-to-native convergence and signed callbacks | [User synchronization](docs/user-synchronization.md) |
| Controlled import of existing native users | [Imports](IMPORTING.md) |
| Remembered host resource filters | [Application context](APPLICATION-CONTEXT.md) |
| Fixed outbound workers and downstream requests | [Service targets](SERVICE-TARGETS.md) |
| Local lifecycle and profile notifications | [Events](docs/events.md) |
| Supported PHP entry points | [API reference](resources/boost/skills/nvl-auth-identity-bridge/references/api.md), [consumer catalog](resources/consumer-api.json) |

Resolve a trusted named consumer with `Identity::consumer($trustedName, $request)` and obtain services from that graph. Use `Identity::browser()` only on an admitted browser request. Preserve issuer/client/application/subject/session bindings, independent cookies, PKCE/nonce, one-use intents, Origin/CSRF checks, live deadlines and final write fences. Keep the actor distinct from a delegated effective subject. Never associate accounts by email, derive authority from native rows or replay an ambiguous write under a new idempotency key.

## Agent integration

Publish the complete portable skill with `php artisan vendor:publish --tag=nvl-auth-identity-bridge-skills --no-interaction` and invoke `$nvl-auth-identity-bridge`. The [entry point](resources/boost/skills/nvl-auth-identity-bridge/SKILL.md), [usage](resources/boost/skills/nvl-auth-identity-bridge/references/usage.md) and [workflow recipes](resources/boost/skills/nvl-auth-identity-bridge/references/workflows.md) remain usable from the installed package without a provider checkout. Laravel Boost can also discover the packaged skill when installed as a consumer development tool.

## Verification

From the suite source checkout, run `herd php tools/run-package-tests.php auth-identity-bridge --concurrency=1`. In a standalone development checkout with development dependencies installed, run `composer --no-plugins verify`. Default tests use isolated SQLite. `phpunit.postgres.xml` is a separately opted-in PostgreSQL qualification; it does not establish MySQL, MariaDB or production adapter coverage.

The source suite owns release certification; GitHub publishing workflows deliver locally certified artifacts. Test output and release receipts apply to their exact source snapshot. Package tests, metadata checks and dependency audits do not establish genuine provider interoperability, browser acceptance, external callback delivery, database contention or deployment readiness. See [contributing](CONTRIBUTING.md), [security](SECURITY.md) and [changelog](CHANGELOG.md).
