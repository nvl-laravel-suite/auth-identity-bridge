<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Oidc;

use Facile\JoseVerifier\Exception\InvalidTokenClaimException;
use Facile\JoseVerifier\Exception\InvalidTokenExceptionInterface;
use Facile\OpenIDClient\Client\ClientBuilder;
use Facile\OpenIDClient\Client\ClientInterface as OpenIdClient;
use Facile\OpenIDClient\Client\Metadata\ClientMetadata;
use Facile\OpenIDClient\Exception\OAuth2Exception;
use Facile\OpenIDClient\Issuer\Issuer;
use Facile\OpenIDClient\Issuer\Metadata\IssuerMetadata;
use Facile\OpenIDClient\Service\AuthorizationService;
use Facile\OpenIDClient\Service\Builder\AuthorizationServiceBuilder;
use Facile\OpenIDClient\Service\Builder\UserInfoServiceBuilder;
use Facile\OpenIDClient\Token\TokenSet;
use Facile\OpenIDClient\Token\TokenSetInterface;
use GuzzleHttp\Psr7\HttpFactory;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/** Standard OIDC transport and verification; browser state belongs to Laravel's transaction store. */
final class OidcClient
{
    private ?OpenIdClient $client = null;

    private ?array $clientMetadata = null;

    private readonly ClientInterface $transport;

    public function __construct(private readonly IdentityConfig $config, IdentityHttp $http)
    {
        // Every library request, including JWKS refreshes, follows the same bounded transport.
        $this->transport = new class($http) implements ClientInterface
        {
            public function __construct(private readonly IdentityHttp $http) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $response = $this->http->sendPsr($request);
                if ($response->getStatusCode() === 429) {
                    throw new IdentityException('rate_limited', 429);
                }
                if ($response->getStatusCode() >= 500) {
                    throw new IdentityException('oidc_unavailable', 503);
                }

                return $response;
            }
        };
        $this->http = $http;
    }

    private readonly IdentityHttp $http;

    public function metadata(): array
    {
        return $this->guard(function (): array {
            $metadata = (new TrustedProviderMetadata($this->config, $this->http))->discovery();
            if (($metadata['issuer'] ?? null) !== $this->config->issuer()) {
                throw new IdentityException('oidc_metadata_invalid', 502);
            }
            foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'] as $name) {
                $this->trustedEndpoint($metadata[$name] ?? null);
            }
            if (isset($metadata['end_session_endpoint'])) {
                $this->trustedEndpoint($metadata['end_session_endpoint']);
            }
            $algorithm = $this->algorithm();
            if (! in_array($algorithm, $metadata['id_token_signing_alg_values_supported'] ?? [], true)) {
                throw new IdentityException('oidc_algorithm_unavailable', 503);
            }

            return $metadata;
        });
    }

    public function authorization(array $intent): string
    {
        return $this->guard(function () use ($intent): string {
            $this->validateIntent($intent);
            $params = [
                'redirect_uri' => $this->redirectUri(),
                'scope' => 'openid profile email offline_access',
                'response_type' => 'code',
                'state' => $intent['state'],
                'nonce' => $intent['nonce'],
                'code_challenge_method' => 'S256',
                'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $intent['verifier'], true)), '+/', '-_'), '='),
            ];
            if ($intent['resource']) {
                $params['resource'] = $this->resource();
            }
            if (isset($intent['prompt'])) {
                if (! in_array($intent['prompt'], ['login', 'none', 'consent', 'select_account'], true)) {
                    throw new IdentityException('oidc_intent_invalid', 400);
                }
                $params['prompt'] = $intent['prompt'];
            }

            return $this->authorizationService()->getAuthorizationUri($this->client(), $params);
        });
    }

    public function exchange(array $callback, array $intent): array
    {
        return $this->guard(function () use ($callback, $intent): array {
            $this->validateIntent($intent);
            if (! is_string($callback['state'] ?? null) || ! hash_equals($intent['state'], $callback['state'])
                || ! $this->nonempty($callback['code'] ?? null)
                || array_intersect(['access_token', 'id_token', 'refresh_token', 'response', 'error'], array_keys($callback)) !== []
                || (isset($callback['iss']) && $callback['iss'] !== $this->config->issuer())) {
                throw new IdentityException('oidc_callback_invalid', 401);
            }
            $params = [
                'grant_type' => 'authorization_code',
                'code' => $callback['code'],
                'redirect_uri' => $this->redirectUri(),
                'code_verifier' => $intent['verifier'],
            ];
            if ($intent['resource']) {
                $params['resource'] = $this->resource();
            }
            // Facile's callback helper does not forward resource parameters to the grant.
            // Its grant and verifier keep the maintained protocol and JOSE implementations.
            $grantStarted = time();
            $set = $this->authorizationService()->grant($this->client(), $params);
            $idToken = $set->getIdToken();
            if (! $this->nonempty($idToken)) {
                throw new IdentityException('oidc_token_invalid', 401);
            }
            $claims = (new IdTokenVerifierBuilder)->build($this->client())
                ->withNonce($intent['nonce'])
                ->withState($intent['state'])
                ->withCode($callback['code'])
                ->withAccessToken($set->getAccessToken())
                ->verify($idToken);
            // The library's nonce checker validates a present claim; this makes it mandatory.
            if (($claims['nonce'] ?? null) !== $intent['nonce']) {
                throw new IdentityException('oidc_token_invalid', 401);
            }
            $this->validateClaims($claims);

            return $this->bundle($set, $claims, $intent['resource'], $grantStarted, $claims['exp']);
        });
    }

    public function refresh(array $tokens): array
    {
        return $this->guard(function () use ($tokens): array {
            if (! $this->nonempty($tokens['refresh_token'] ?? null)
                || ! $this->nonempty($tokens['subject'] ?? null)
                || ! $this->nonempty($tokens['sid'] ?? null)
                || ! is_bool($tokens['resource'] ?? null)
                || ! is_array($tokens['claims'] ?? null)
                || ! $this->nonempty($tokens['id_token'] ?? null)) {
                throw new IdentityException('reauthentication_required', 401);
            }
            $params = $tokens['resource'] ? ['resource' => $this->resource()] : [];
            $grantStarted = time();
            $set = $this->authorizationService()->refresh($this->client(), $tokens['refresh_token'], $params);
            $newIdToken = $set->getIdToken() !== null;
            $claims = $set->getIdToken() !== null ? $set->claims() : $tokens['claims'];
            $this->validateClaims($claims);
            if ($claims['sub'] !== $tokens['subject'] || $claims['sid'] !== $tokens['sid']
                || (isset($claims['nonce']) && $claims['nonce'] !== ($tokens['claims']['nonce'] ?? null))) {
                throw new IdentityException('oidc_token_invalid', 401);
            }
            if ($set->getIdToken() === null) {
                $set = $set->withIdToken($tokens['id_token']);
            }
            $result = $this->bundle($set, $claims, $tokens['resource'], $grantStarted, $newIdToken ? $claims['exp'] : null);
            $result['refresh_token'] = $result['refresh_token'] ?? $tokens['refresh_token'];

            return $result;
        });
    }

    public function userInfo(string $accessToken, string $expectedSubject): array
    {
        return $this->guard(function () use ($accessToken, $expectedSubject): array {
            if (! $this->nonempty($accessToken) || ! $this->nonempty($expectedSubject, 128)) {
                throw new IdentityException('oidc_token_invalid', 401);
            }
            $service = (new UserInfoServiceBuilder)
                ->setHttpClient($this->transport)
                ->setRequestFactory(new HttpFactory)
                ->build();
            $user = $service->getUserInfo($this->client(), TokenSet::fromParams([
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
            ]));
            if (($user['sub'] ?? null) !== $expectedSubject) {
                throw new IdentityException('oidc_userinfo_invalid', 401);
            }

            return $user;
        });
    }

    /** Uses OP confirmation rather than putting an ID token in a rendered URL. */
    public function centralLogoutUrl(string $state): string
    {
        return $this->guard(function () use ($state): string {
            if (! $this->nonempty($state, 512)) {
                throw new IdentityException('oidc_intent_invalid', 400);
            }
            $endpoint = $this->metadata()['end_session_endpoint'] ?? null;
            $this->trustedEndpoint($endpoint);
            $destination = $this->config->value('browser.post_logout_redirect_uri', $this->config->appOrigin().'/signed-out');
            $this->appDestination($destination);

            return $endpoint.'?'.http_build_query([
                'client_id' => $this->config->clientId(),
                'post_logout_redirect_uri' => $destination,
                'state' => $state,
            ], '', '&', PHP_QUERY_RFC3986);
        });
    }

    private function client(): OpenIdClient
    {
        $metadata = $this->metadata();
        if ($this->client !== null && $this->clientMetadata === $metadata) {
            return $this->client;
        }
        $credentials = $this->config->credentials('browser');
        $jwks = new TrustedProviderMetadata($this->config, $this->http);

        $client = (new ClientBuilder)
            ->setIssuer(new Issuer(IssuerMetadata::fromArray($metadata), $jwks))
            ->setClientMetadata(ClientMetadata::fromArray([
                'client_id' => $credentials['id'],
                'client_secret' => $credentials['secret'],
                'redirect_uris' => [$this->redirectUri()],
                'response_types' => ['code'],
                'token_endpoint_auth_method' => 'client_secret_basic',
                'id_token_signed_response_alg' => $this->algorithm(),
            ]))
            ->setHttpClient($this->transport)
            ->build();
        $this->clientMetadata = $metadata;

        return $this->client = $client;
    }

    private function authorizationService(): AuthorizationService
    {
        return (new AuthorizationServiceBuilder)
            ->setHttpClient($this->transport)
            ->setRequestFactory(new HttpFactory)
            ->setIdTokenVerifierBuilder(new IdTokenVerifierBuilder)
            ->build();
    }

    private function bundle(TokenSetInterface $set, array $claims, bool $resource, int $grantStarted, ?int $idTokenExpiresAt): array
    {
        $attributes = $set->getAttributes();
        if (! $this->nonempty($attributes['access_token'] ?? null)
            || ! is_int($attributes['expires_in'] ?? null) || $attributes['expires_in'] <= 0 || $attributes['expires_in'] > 300
            || ! is_string($attributes['token_type'] ?? null) || strcasecmp($attributes['token_type'], 'Bearer') !== 0
            || (isset($attributes['refresh_token']) && ! $this->nonempty($attributes['refresh_token']))) {
            throw new IdentityException('oidc_token_invalid', 401);
        }
        $expiresAt = min($grantStarted + $attributes['expires_in'], $idTokenExpiresAt ?? PHP_INT_MAX);
        $user = $this->userInfo($attributes['access_token'], $claims['sub']);
        if ($expiresAt <= time()) {
            throw new IdentityException('oidc_unavailable', 503);
        }

        return array_filter([
            'access_token' => $attributes['access_token'],
            'refresh_token' => $attributes['refresh_token'] ?? null,
            'id_token' => $set->getIdToken(),
            'expires_at' => $expiresAt,
            'subject' => $claims['sub'],
            'sid' => $claims['sid'],
            'claims' => $claims,
            'userinfo' => $user,
            'resource' => $resource,
        ], static fn ($value) => $value !== null);
    }

    private function validateClaims(array $claims): void
    {
        if (! $this->nonempty($claims['sub'] ?? null, 128) || ! $this->nonempty($claims['sid'] ?? null, 128)
            || (array_key_exists('urn:identity-platform:application', $claims) && $claims['urn:identity-platform:application'] !== $this->config->applicationId())
            || (array_key_exists('azp', $claims) && $claims['azp'] !== $this->config->clientId())
            || (is_array($claims['aud'] ?? null) && count($claims['aud']) > 1 && ($claims['azp'] ?? null) !== $this->config->clientId())) {
            throw new IdentityException('oidc_token_invalid', 401);
        }
    }

    private function validateIntent(array $intent): void
    {
        if (! $this->nonempty($intent['state'] ?? null, 512) || ! $this->nonempty($intent['nonce'] ?? null, 512)
            || ! is_string($intent['verifier'] ?? null) || ! preg_match('/^[A-Za-z0-9._~-]{43,128}$/D', $intent['verifier'])
            || ! is_bool($intent['resource'] ?? null)) {
            throw new IdentityException('oidc_intent_invalid', 400);
        }
    }

    private function algorithm(): string
    {
        $algorithm = $this->config->value('browser.id_token_algorithm', 'EdDSA');
        if (! in_array($algorithm, ['EdDSA', 'ES256', 'RS256'], true)) {
            throw new IdentityException('oidc_algorithm_unavailable', 503);
        }

        return $algorithm;
    }

    private function trustedEndpoint(mixed $endpoint): void
    {
        $parts = is_string($endpoint) ? parse_url($endpoint) : false;
        $origin = parse_url($this->config->origin());
        if (! $parts || ($parts['scheme'] ?? null) !== 'https' || ($parts['host'] ?? null) !== ($origin['host'] ?? null)
            || ($parts['port'] ?? 443) !== ($origin['port'] ?? 443)
            || isset($parts['user'], $parts['pass']) || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['fragment']) || isset($parts['query']) || preg_match('/[\x00-\x20\x7f\\\\]/', $endpoint)) {
            throw new IdentityException('oidc_metadata_invalid', 502);
        }
    }

    private function appDestination(mixed $destination): void
    {
        if (! is_string($destination) || ! str_starts_with($destination, $this->config->appOrigin().'/')
            || ! filter_var($destination, FILTER_VALIDATE_URL) || str_contains($destination, '#')
            || preg_match('/[\x00-\x20\x7f\\\\]/', $destination)) {
            throw new IdentityException('oidc_destination_invalid', 503);
        }
    }

    private function redirectUri(): string
    {
        $destination = $this->config->value('browser.redirect_uri', $this->config->appOrigin().'/auth/callback');
        $this->appDestination($destination);

        return $destination;
    }

    private function resource(): string
    {
        return 'urn:identity-platform:application:'.$this->config->applicationId();
    }

    private function nonempty(mixed $value, int $maximum = 8192): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $maximum && ! preg_match('/[\x00-\x1f\x7f]/', $value);
    }

    private function guard(callable $work): mixed
    {
        try {
            return $work();
        } catch (IdentityException $error) {
            throw $error;
        } catch (OAuth2Exception $error) {
            throw new IdentityException(in_array($error->getError(), ['invalid_grant', 'invalid_token', 'access_denied'], true) ? 'reauthentication_required' : 'oidc_unavailable', in_array($error->getError(), ['invalid_grant', 'invalid_token', 'access_denied'], true) ? 401 : 503);
        } catch (InvalidTokenClaimException $error) {
            throw new IdentityException(in_array($error->getClaim(), ['at_hash', 'c_hash', 's_hash'], true) ? 'oidc_token_hash_invalid' : 'oidc_token_invalid', 401);
        } catch (InvalidTokenExceptionInterface) {
            throw new IdentityException('oidc_token_invalid', 401);
        } catch (Throwable) {
            // Do not chain vendor exceptions: protocol messages can contain credentials or claims.
            throw new IdentityException('oidc_unavailable', 503);
        }
    }
}
