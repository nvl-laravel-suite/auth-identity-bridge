# Changelog

## [Unreleased]

## [7.0.2] - 2026-11-11

### Fixed

- Match retained consumer commands, their receipts, redeemed delegation versions and the selected application context regardless of JSON object key order, so MySQL's native JSON columns no longer turn replays into `idempotency_conflict`, lose commit recovery or clear a valid context.
- Send provider requests without the host's global HTTP client middleware and options, so an ambient retry cannot replay a single-use code, refresh or import request and ambient credentials, headers or URL rewrites cannot reach the provider.
- Stop a provider download as soon as it exceeds the configured response limit instead of only checking the size after buffering it.
- Refuse an ID token signed with any algorithm other than the configured one as `oidc_token_invalid` (401) rather than reporting a provider outage.
- Keep access, refresh, authorization-code, login-state and resource credentials out of exception stack-trace arguments.
- Make `IdentityLogin`, `IdentitySession` and `IdentityInbox` mass-prunable so the host's `model:prune` schedule removes abandoned sign-in transactions, sessions past their absolute deadline and receipts beyond every replay window; these rows previously accumulated forever.
- Keep delegated reporting capabilities and consumer operation input out of exception stack-trace arguments (`ConsumerClient::call()` and `::report()` now mark those parameters sensitive).
- Refuse a value of the wrong backing type in the `EnumValue` native transform as `native_transform_invalid` instead of raising a `TypeError`.
- Remove the unreferenced internal `Support\IdentityPsrClient`; the OIDC client already sends every library request through its own bounded transport.
- Require Laravel 13.30 or later. The package calls `Lock::refresh()` and `Http::withoutGlobalConfiguration()`, which earlier 13.x releases do not provide.

<!-- NVL GENERATED CHANGES START -->
### Changed

- bound provider responses and correct journal and sync edge cases
<!-- NVL GENERATED CHANGES END -->

## [7.0.1] - 2026-11-05

### Fixed

- Require patched Symfony HTTP Foundation 7.4.23+/8.1.11+ and reject affected HTTP Kernel and Routing releases in standalone installations, independently of Core's dependency protections.

<!-- NVL GENERATED CHANGES START -->
### Changed

- require patched Symfony components
- Merge remote-tracking branch 'origin/main'
<!-- NVL GENERATED CHANGES END -->

## [7.0.0] - 2026-11-03

- Add the existing Identity Platform Laravel consumer as the independently installable nvl/auth-identity-bridge package. Preserve its PHP API, migrations and security boundaries.
- Add opt-in Composer discovery and suite package/test integration.

- Recheck local session liveness before returning generic consumer responses, including after provider waits and option-cache hits. Preserve typed managed commit/recovery outcomes.
- Expand the portable integration skill with source routing and practical browser, data, recovery, synchronization and scoped-impersonation workflows.

- Clear bridge release conformance with strict executable PHP, explicit persistence allowlists on every affected model, and NVL attribution while retaining proprietary terms. Preserve migration names and schema operations.
- Exclude unpatched Symfony MIME below 8.1.10 and document the targeted consumer upgrade.
- Keep the explicitly required foreign-namespace test adapter out of optimized classmap scanning.

- Reject non-string configured model connections with the existing configuration error before handing them to Eloquent; preserve configured and per-model string connections.

- Qualify the complete bridge at PHPStan max with validated wire/configuration contracts and accurate Eloquent types; retain authorization and expiry fences. Reject malformed cached JWKS, refresh expiry claims and import subjects; preserve bound-session fluent calls and Laravel Gate event semantics.

- Declare the extensions and direct JOSE, URI, Carbon, PSR and HTTP foundation dependencies already used by the bridge, so isolated installs and dependency-boundary checks do not rely on incidental transitive requirements.

- Publish identity-config before authentication is enabled and complete portable API, installation and event references. Keep the standalone Laravel merge behavior, machine protocols and existing schema intact in suite diagnostics and qualification.
