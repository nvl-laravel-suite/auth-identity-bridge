# Upgrading

The initial suite package uses the 7.x family version. Replace the Composer requirement `identity-platform/laravel` with `nvl/auth-identity-bridge`. PHP imports remain `IdentityPlatform\Laravel`. Publish the bridge configuration and explicitly enable it after configuring named consumers. Preserve existing tables, migration history, keys, credentials, session ownership and callback configuration; do not reset the database.

## Symfony MIME security floor

Laravel 13 consumers must use `symfony/mime` 8.1.10 or newer for [CVE-2026-45070](https://symfony.com/blog/cve-2026-45070-email-header-injection-via-non-token-characters-in-mime-parameter-names). This bridge rejects older MIME versions. Update the bridge and that transitive package together with `composer update nvl/auth-identity-bridge symfony/mime --with-dependencies --minimal-changes`, review the lock diff, then run `composer audit --locked` and the consuming app's affected tests. Commit the host lock file in the host's own repository.

Internal persistence models now use explicit field allowlists. Call package services for mutations; host applications must not depend on mass-assigning arbitrary attributes into internal bridge models. Explicitly loaded test adapter fixtures remain available through their existing `require_once`; only optimized classmap scanning excludes their foreign namespace.
