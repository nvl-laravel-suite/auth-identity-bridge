<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Oidc;

use Facile\JoseVerifier\JWK\JwksProviderInterface;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Cache;

/** Shared public metadata from fixed configured endpoints, with bounded key rotation refresh. */
final class TrustedProviderMetadata implements JwksProviderInterface
{
    private bool $refresh = false;

    public function __construct(private IdentityConfig $config, private IdentityHttp $http) {}

    /** @return array<array-key, mixed> */
    public function discovery(): array
    {
        return $this->cached('discovery', function (): array {
            $metadata = $this->http->get($this->config->issuer().'/.well-known/openid-configuration');
            if (($metadata['issuer'] ?? null) !== $this->config->issuer() || ($metadata['jwks_uri'] ?? null) !== $this->config->issuer().'/jwks') {
                throw new IdentityException('oidc_metadata_invalid', 502);
            }

            return $metadata;
        });
    }

    /** @return array{keys: list<array<string, mixed>>, ...<array-key, mixed>} */
    public function getJwks(): array
    {
        $refresh = $this->refresh;
        $this->refresh = false;

        $jwks = $this->cached('jwks', function (): array {
            $this->discovery();
            $jwks = $this->http->get($this->config->issuer().'/jwks');
            if (! isset($jwks['keys']) || ! is_array($jwks['keys']) || ! array_is_list($jwks['keys']) || count($jwks['keys']) > 100) {
                throw new IdentityException('oidc_keys_invalid', 502);
            }

            return $jwks;
        }, $refresh);
        if (! is_array($jwks['keys'] ?? null) || ! array_is_list($jwks['keys']) || count($jwks['keys']) > 100) {
            throw new IdentityException('oidc_keys_invalid', 502);
        }
        $keys = [];
        foreach ($jwks['keys'] as $key) {
            if (! is_array($key)) {
                throw new IdentityException('oidc_keys_invalid', 502);
            }
            $entry = [];
            foreach ($key as $name => $value) {
                if (! is_string($name)) {
                    throw new IdentityException('oidc_keys_invalid', 502);
                }
                $entry[$name] = $value;
            }
            $keys[] = $entry;
        }
        $jwks['keys'] = $keys;

        return $jwks;
    }

    public function reload(): static
    {
        $this->refresh = true;

        return $this;
    }

    /**
     * @param  callable(): array<array-key, mixed>  $load
     * @return array<array-key, mixed>
     */
    private function cached(string $name, callable $load, bool $refresh = false): array
    {
        $cache = Cache::store($this->config->value('lock_store'));
        $key = 'identity-oidc:'.hash('sha256', $this->config->issuer()).':'.$name;
        $cached = $cache->get($key);
        if (is_array($cached) && ! $refresh) {
            return $cached;
        }
        $store = $cache->getStore();
        if (! $store instanceof LockProvider) {
            throw new IdentityException('oidc_metadata_unavailable', 503);
        }
        try {
            $value = $store->lock($key.':lock', 15)->block(3, function () use ($cache, $key, $load, $refresh): array {
                $cached = $cache->get($key);
                if (is_array($cached) && (! $refresh || ! $cache->add($key.':refresh', true, 30))) {
                    return $cached;
                }
                $value = $load();
                $cache->put($key, $value, 300);

                return $value;
            });
            if (! is_array($value)) {
                throw new IdentityException('oidc_metadata_unavailable', 503);
            }

            return $value;
        } catch (LockTimeoutException) {
            throw new IdentityException('oidc_metadata_unavailable', 503);
        }
    }
}
