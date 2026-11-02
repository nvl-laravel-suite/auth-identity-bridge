<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Oidc;

use Facile\JoseVerifier\JWK\JwksProviderInterface;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Cache;

/** Shared public metadata from fixed configured endpoints, with bounded key rotation refresh. */
final class TrustedProviderMetadata implements JwksProviderInterface
{
    private bool $refresh = false;

    public function __construct(private IdentityConfig $config, private IdentityHttp $http) {}

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

    public function getJwks(): array
    {
        $refresh = $this->refresh;
        $this->refresh = false;

        return $this->cached('jwks', function (): array {
            $this->discovery();
            $jwks = $this->http->get($this->config->issuer().'/jwks');
            if (! isset($jwks['keys']) || ! is_array($jwks['keys']) || ! array_is_list($jwks['keys']) || count($jwks['keys']) > 100) {
                throw new IdentityException('oidc_keys_invalid', 502);
            }

            return $jwks;
        }, $refresh);
    }

    public function reload(): static
    {
        $this->refresh = true;

        return $this;
    }

    private function cached(string $name, callable $load, bool $refresh = false): array
    {
        $cache = Cache::store($this->config->value('lock_store'));
        $key = 'identity-oidc:'.hash('sha256', $this->config->issuer()).':'.$name;
        $cached = $cache->get($key);
        if (is_array($cached) && ! $refresh) {
            return $cached;
        }
        try {
            return $cache->lock($key.':lock', 15)->block(3, function () use ($cache, $key, $load, $refresh): array {
                $cached = $cache->get($key);
                if (is_array($cached) && (! $refresh || ! $cache->add($key.':refresh', true, 30))) {
                    return $cached;
                }
                $value = $load();
                $cache->put($key, $value, 300);

                return $value;
            });
        } catch (LockTimeoutException) {
            throw new IdentityException('oidc_metadata_unavailable', 503);
        }
    }
}
