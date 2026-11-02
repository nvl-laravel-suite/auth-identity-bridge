# Contributing

Develop the canonical source in `packages/nvl/auth-identity-bridge`. Use the existing public `IdentityPlatform\Laravel` entrypoints and preserve trusted consumer binding, host-owned native data, authorization and durable recovery boundaries.

Run `herd php tools/run-package-tests.php auth-identity-bridge` from the suite. New package tests use Pest with isolated Testbench stores. Keep real credentials, private environments, proof URLs, vendor files and local stores out of contributions. Coordinate current provider/client contracts when changing behavior; unit tests do not establish live or deployment qualification.

The published package repository is a read-only release mirror. Pull requests to the mirror are not accepted. Open a public issue for reproducible problems without secrets; implementation changes belong in the private source repository and are delivered as immutable releases.
