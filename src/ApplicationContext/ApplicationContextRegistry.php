<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\ApplicationContext;

use IdentityPlatform\Laravel\Exceptions\IdentityException;

/** Trusted host boot registration only; requests never choose a class or service name.
 * @api
 */
final class ApplicationContextRegistry
{
    /** @var array<string, array<string, class-string<ApplicationContextProvider>>> */
    private array $providers = [];

    /** @param string $provider Trusted registration validates the implementation class at runtime. */
    public function register(string $consumer, string $kind, string $provider): void
    {
        if (! preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $kind) || ! is_a($provider, ApplicationContextProvider::class, true) || isset($this->providers[$consumer][$kind])) {
            throw new IdentityException('application_context_registration_invalid');
        }
        $this->providers[$consumer][$kind] = $provider;
    }

    /**
     * @return class-string<ApplicationContextProvider>
     */
    public function provider(string $consumer, string $kind): string
    {
        return $this->providers[$consumer][$kind] ?? throw new IdentityException('application_context_unknown', 422);
    }
}
