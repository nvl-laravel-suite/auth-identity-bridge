<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Services;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Support\ServiceTargetContext;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * Independently scoped worker credentials and generation-bound encrypted token cache.
 *
 * @api Obtain this target-bound handle through ServiceTokenManager::target().
 *
 * @phpstan-type CacheRecord array{binding: string, key: string, scopes: non-empty-list<non-empty-string>, generation: non-empty-string, digest: non-empty-string, issued_at: int|float, expires_at: int|float, ...<array-key, mixed>}
 * @phpstan-type TokenEntry array{binding: string, key: string, scopes: non-empty-list<non-empty-string>, generation: non-empty-string, digest: non-empty-string, issued_at: int|float, expires_at: int|float, token: non-empty-string, ...<array-key, mixed>}
 */
final class ServiceTokenClient
{
    public function __construct(private ServiceTargetContext $config, private IdentityHttp $http) {}

    /** @param array<array-key, mixed> $scopes */
    public function token(array $scopes = []): string
    {
        $this->guard();
        $scopes = $this->scopes(func_num_args() === 0 ? $this->config->scopes() : $scopes);
        $key = $this->cacheKey($scopes);

        try {
            $cache = Cache::store($this->config->value('cache_store'));

            $store = $cache->getStore();
            Contract::require($store instanceof LockProvider, 'service_token_unavailable', 503);

            $token = $store->lock($key.':lock', 30)->block(5, function () use ($cache, $key, $scopes): string {
                $this->guard();
                $entry = $this->entry($cache->get($key), $key, $scopes);
                if ($entry !== null && $entry['expires_at'] > microtime(true) + 5) {
                    $index = $this->index($cache->get($this->tokenIndex($entry['token'])), $entry['token']);
                    if ($this->matches($entry, $index)) {
                        $this->guard();

                        if ($entry['expires_at'] > microtime(true) + 5) {
                            return $entry['token'];
                        }
                    }
                }
                $this->guard();
                $started = microtime(true);
                $result = $this->http->form('/api/service-auth/oauth2/token', ['grant_type' => 'client_credentials', 'resource' => $this->audience(), 'scope' => implode(' ', $scopes)], 'service');
                $expiresIn = $result['expires_in'] ?? null;
                Contract::require(array_diff(array_keys($result), ['access_token', 'token_type', 'expires_in', 'expires_at', 'scope']) === []
                    && $this->validToken($result['access_token'] ?? null)
                    && is_string($result['token_type'] ?? null) && strcasecmp($result['token_type'], 'Bearer') === 0
                    && is_string($result['scope'] ?? null), 'invalid_service_token_response', 502);
                Contract::require(is_int($expiresIn) && $expiresIn > 0 && $expiresIn <= 300, 'invalid_service_token_response', 502);
                $expires = $started + $expiresIn;
                try {
                    $returned = $this->scopes(explode(' ', $result['scope']));
                } catch (IdentityException) {
                    throw new IdentityException('invalid_service_token_response', 502);
                }
                Contract::require($returned === $scopes, 'invalid_service_token_response', 502);
                if (array_key_exists('expires_at', $result)) {
                    Contract::require(is_int($result['expires_at']) && $result['expires_at'] > 0, 'invalid_service_token_response', 502);
                    $expires = min($expires, $result['expires_at']);
                }
                $this->guard();
                Contract::require($expires > microtime(true), 'service_token_expired', 503);
                $remaining = (int) floor($expires - microtime(true));
                if ($remaining > 5) {
                    $record = ['binding' => $this->binding(), 'key' => $key, 'scopes' => $scopes, 'generation' => bin2hex(random_bytes(24)), 'digest' => hash('sha256', $result['access_token']), 'issued_at' => $started, 'expires_at' => $expires];
                    // Confirm the encrypted index before a reusable token can exist. A
                    // token-store write may commit and then throw; its index is retained.
                    $sealedIndex = Crypt::encryptString(json_encode($record, JSON_THROW_ON_ERROR));
                    $sealedEntry = Crypt::encryptString(json_encode($record + ['token' => $result['access_token']], JSON_THROW_ON_ERROR));
                    $this->guard();
                    Contract::require($cache->put($this->tokenIndex($result['access_token']), $sealedIndex, $remaining) === true, 'service_cache_unavailable', 503);
                    $this->guard();
                    Contract::require($cache->put($key, $sealedEntry, $remaining - 5) === true, 'service_cache_unavailable', 503);
                }

                $this->guard();
                $remainingAfterCache = $expires - microtime(true);
                Contract::require($remainingAfterCache > 0, 'service_token_expired', 503);

                return $result['access_token'];
            });
            Contract::require(is_string($token), 'service_token_unavailable', 503);

            return $token;
        } catch (IdentityException $error) {
            if (in_array($error->status, [401, 403], true) && $error->errorCode !== 'delegation_outbound_forbidden') {
                throw new IdentityException('service_authentication_failed', 503);
            }
            throw $error;
        } catch (Throwable) {
            throw new IdentityException('service_token_unavailable');
        }
    }

    public function revoke(#[\SensitiveParameter] string $token): void
    {
        $this->guard();
        Contract::require($this->validToken($token), 'invalid_service_token', 400);
        try {
            $cache = Cache::store($this->config->value('cache_store'));
            $indexKey = $this->tokenIndex($token);
            $index = $this->index($cache->get($indexKey), $token);
            $this->guard();
            $this->http->form('/api/service-auth/oauth2/revoke', ['token' => $token, 'token_type_hint' => 'access_token'], 'service');
            if ($index === null) {
                return;
            }
            $store = $cache->getStore();
            Contract::require($store instanceof LockProvider, 'service_token_unavailable', 503);
            $store->lock($index['key'].':lock', 30)->block(5, function () use ($cache, $indexKey, $index, $token): void {
                $this->guard();
                $entry = $this->entry($cache->get($index['key']), $index['key'], $index['scopes']);
                if ($this->matches($entry, $index) && hash_equals($entry['token'], $token)) {
                    $this->guard();
                    Contract::require($cache->forget($index['key']) === true, 'service_cache_unavailable', 503);
                }
                $current = $this->index($cache->get($indexKey), $token);
                if ($current !== null && $current['generation'] === $index['generation']) {
                    Contract::require($cache->forget($indexKey) === true, 'service_cache_unavailable', 503);
                }
            });
        } catch (IdentityException $error) {
            if (in_array($error->status, [401, 403], true) && $error->errorCode !== 'delegation_outbound_forbidden') {
                throw new IdentityException('service_authentication_failed', 503);
            }
            throw $error;
        } catch (Throwable) {
            throw new IdentityException('service_token_unavailable');
        }
    }

    /** @param array<array-key, mixed> $scopes */
    public function reject(#[\SensitiveParameter] string $token, array $scopes = []): void
    {
        $this->guard();
        Contract::require($this->validToken($token), 'invalid_service_token', 400);
        $scopes = $this->scopes(func_num_args() < 2 ? $this->config->scopes() : $scopes);
        $key = $this->cacheKey($scopes);
        try {
            $cache = Cache::store($this->config->value('cache_store'));
            $store = $cache->getStore();
            Contract::require($store instanceof LockProvider, 'service_token_unavailable', 503);
            $store->lock($key.':lock', 30)->block(5, function () use ($cache, $key, $token, $scopes): void {
                $this->guard();
                $entry = $this->entry($cache->get($key), $key, $scopes);
                if ($entry === null || ! hash_equals($entry['token'], $token)) {
                    return;
                }
                $this->guard();
                Contract::require($cache->forget($key) === true, 'service_cache_unavailable', 503);
                $indexKey = $this->tokenIndex($token);
                if ($this->matches($entry, $this->index($cache->get($indexKey), $token))) {
                    Contract::require($cache->forget($indexKey) === true, 'service_cache_unavailable', 503);
                }
            });
        } catch (IdentityException $error) {
            throw $error;
        } catch (Throwable) {
            throw new IdentityException('service_token_unavailable');
        }
    }

    /** @param array<array-key, mixed> $options */
    public function request(string $relativePath, array $options = []): ResponseInterface
    {
        $this->guard();

        return (new ServiceTargetHttp($this->config))->request($relativePath, $options);
    }

    private function guard(): void
    {
        app(ExecutionPolicy::class)->assertOutboundAllowed();
    }

    /** @phpstan-assert-if-true =non-empty-string $token */
    private function validToken(mixed $token): bool
    {
        return is_string($token) && $token !== '' && strlen($token) <= 60000 && preg_match('/^[A-Za-z0-9._~+\/-]+=*$/D', $token) === 1;
    }

    /** @return non-empty-list<non-empty-string> */
    private function scopes(mixed $scopes): array
    {
        Contract::require(is_array($scopes) && $scopes !== [] && count($scopes) <= 250 && Contract::strings($scopes, true), 'service_scope_invalid', 400);
        foreach ($scopes as $scope) {
            Contract::require(! in_array($scope, ['openid', 'profile', 'email', 'offline_access'], true) && in_array($scope, $this->config->scopes(), true), 'service_scope_invalid', 400);
        }
        sort($scopes, SORT_STRING);

        return $scopes;
    }

    private function binding(): string
    {
        $credentials = $this->config->credentials();

        return hash('sha256', json_encode([$this->config->issuer(), $this->audience(), $credentials['id'], hash('sha256', $credentials['secret'])], JSON_THROW_ON_ERROR));
    }

    /** @param array<array-key, mixed> $scopes */
    private function cacheKey(array $scopes): string
    {
        return 'identity:service:v2:entry:'.hash('sha256', json_encode([$this->binding(), $scopes], JSON_THROW_ON_ERROR));
    }

    private function tokenIndex(#[\SensitiveParameter] string $token): string
    {
        return 'identity:service:v2:index:'.hash('sha256', $this->binding()."\0".hash('sha256', $token));
    }

    /** @return CacheRecord|null */
    private function record(mixed $ciphertext): ?array
    {
        if (! is_string($ciphertext)) {
            return null;
        }
        try {
            $record = json_decode(Crypt::decryptString($ciphertext), true, 16, JSON_THROW_ON_ERROR);
            if (! is_array($record) || ($record['binding'] ?? null) !== $this->binding()
                || ! is_string($record['generation'] ?? null) || preg_match('/^[a-f0-9]{48}$/D', $record['generation']) !== 1
                || ! is_string($record['digest'] ?? null) || preg_match('/^[a-f0-9]{64}$/D', $record['digest']) !== 1
                || ! is_numeric($record['issued_at'] ?? null) || ! is_numeric($record['expires_at'] ?? null)
                || ! (is_float($record['issued_at']) || is_int($record['issued_at'])) || ! (is_float($record['expires_at']) || is_int($record['expires_at']))
                || $record['issued_at'] > microtime(true) || $record['expires_at'] <= microtime(true)
                || $record['expires_at'] > $record['issued_at'] + 300 || $record['expires_at'] <= $record['issued_at']
                || $this->scopes($record['scopes'] ?? null) !== $record['scopes']
                || ($record['key'] ?? null) !== $this->cacheKey($record['scopes'])) {
                return null;
            }

            return $record;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @param  list<string>  $scopes
     * @return TokenEntry|null
     */
    private function entry(mixed $ciphertext, string $key, array $scopes): ?array
    {
        $entry = $this->record($ciphertext);
        if ($entry === null || ($entry['key'] !== $key) || $entry['scopes'] !== $scopes || ! $this->validToken($entry['token'] ?? null) || ! hash_equals($entry['digest'], hash('sha256', $entry['token']))) {
            return null;
        }

        return $entry;
    }

    /** @return CacheRecord|null */
    private function index(mixed $ciphertext, #[\SensitiveParameter] string $token): ?array
    {
        $index = $this->record($ciphertext);
        if ($index === null || array_key_exists('token', $index) || ! hash_equals($index['digest'], hash('sha256', $token))) {
            return null;
        }

        return $index;
    }

    /**
     * @param  TokenEntry|null  $entry
     * @param  CacheRecord|null  $index
     *
     * @phpstan-assert-if-true =TokenEntry $entry
     * @phpstan-assert-if-true =CacheRecord $index
     */
    private function matches(?array $entry, ?array $index): bool
    {
        return $entry !== null && $index !== null && $entry['generation'] === $index['generation'] && $entry['key'] === $index['key'] && $entry['digest'] === $index['digest'] && $entry['expires_at'] === $index['expires_at'];
    }

    private function audience(): string
    {
        return 'urn:identity-platform:application:'.$this->config->applicationId();
    }
}
