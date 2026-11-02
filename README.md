# NVL Auth Identity Bridge

This is a standalone Laravel 13 / PHP 8.4+ consumer bridge. It is locally integrated; no public package release has been published by this change. For local installation, add this repository entry to the consuming app's Composer manifest, then run `composer require nvl/auth-identity-bridge:^7.0`:

```json
{
    "type": "path",
    "url": "/path/to/nvl-laravel-suite/packages/nvl/auth-identity-bridge",
    "options": {
        "symlink": true,
        "versions": {"nvl/auth-identity-bridge": "7.0.0"}
    }
}
```

Publish configuration with `php artisan vendor:publish --tag=nvl-auth-identity-bridge-config`. Configure the existing `identity.php` issuer, application, named consumers, native mapping, credentials, shared lock store and session ownership. Set `enabled` to `true` in `config/nvl-auth-identity-bridge.php` only after configuration. Run `php artisan migrate` on the intended consumer database, then `php artisan nvl:auth-identity-bridge:doctor --strict`.

The bridge is disabled by default, so merely installing the suite does not change host authentication or middleware. Enabled requests retain the original strict issuer/client/application/subject/session bindings. The established `IdentityPlatform\Laravel` PHP API and `identity` configuration remain unchanged. It works with a host-owned Authenticatable model and does not require `nvl/auth`. Shared profiles and native users never grant permission authority.

The suite is the canonical source. The Identity development checkout links to this package; runtime consumers require no provider source/database or suite workbench. Composer discovery registers the bridge provider. The package retains its existing proprietary license; this local addition does not publish a remote release.

Use `herd php tools/run-package-tests.php auth-identity-bridge` from the suite for the isolated package suite, or `composer --no-plugins verify` from a standalone development checkout with its development dependencies installed. Default tests use isolated SQLite; the existing `phpunit.postgres.xml` remains a separately opted-in PostgreSQL qualification, not a claim about the suite's other database engines.

See [headless lifecycle](HEADLESS-LIFECYCLE.md), [authorization](AUTHORIZATION.md), [native imports](IMPORTING.md), [managed consumers](CONSUMER-MANAGEMENT.md), [application context](APPLICATION-CONTEXT.md) and [service targets](SERVICE-TARGETS.md).

## Agent integration skill

Publish the portable skill with `php artisan vendor:publish --tag=nvl-auth-identity-bridge-skills` and invoke `$nvl-auth-identity-bridge`. Its [entrypoint](resources/boost/skills/nvl-auth-identity-bridge/SKILL.md) routes tasks to the installed contracts; its [workflow recipes](resources/boost/skills/nvl-auth-identity-bridge/references/workflows.md) cover data ownership, browser lifecycle, self/managed operations, original-command recovery, versioned native convergence, imports, authorization and scoped impersonation. The skill remains usable after publication without a provider checkout.

## Verification and release boundary

The bridge-only source snapshot passed all 1,095 package tests / 4,271 assertions, including 18 model-guard regressions, disabled-host boot, explicit activation and the delayed-response expiry fence. The 19 affected persistence-model files also passed PHPStan at level max. The independent native sample passed 112 tests / 818 assertions with two root-owned opt-in appearance collectors skipped. Those skips are not browser acceptance; the previous owned native HTTPS/HTTP2 invitation journey remains a separate receipt.

The bridge now has strict declarations in its executable PHP, explicit per-model persistence fields and the intended NVL holder attribution. The license remains proprietary. Migration filenames and schema operations are unchanged; declarations were added to their PHP headers. The family validator reports zero bridge violations. The active worktree still reports eight unrelated template-package violations, which this bridge change leaves untouched.

The bridge excludes Symfony MIME versions below 8.1.10 for its Laravel 13 consumers. The native sample was patched from 8.1.7 to 8.1.10 with no other dependency version changes, and its locked Composer audit reports no advisories. Existing consumers should follow [upgrading](UPGRADING.md). Package tests, metadata/conformance checks and dependency audit do not establish full appearance, database-engine contention, external callback delivery or VPS deployment acceptance.
