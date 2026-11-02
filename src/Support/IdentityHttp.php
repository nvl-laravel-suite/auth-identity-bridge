<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use GuzzleHttp\Psr7\Response as PsrResponse;
use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

class IdentityHttp
{
    public function __construct(private IdentityConfig|ServiceTargetContext $config) {}

    /**
     * @param  array<array-key, string>  $headers
     * @return array<array-key, mixed>
     */
    public function get(string $path, array $headers = []): array
    {
        return $this->decode($this->request('GET', $path, null, $headers));
    }

    /**
     * @param  array<array-key, mixed>  $payload
     * @return array<array-key, mixed>
     */
    public function json(string $path, array $payload, string $plane = 'browser', bool $preserveObjectKinds = false): array
    {
        $consumer = str_starts_with($path, '/api/consumer/v1/');

        return $this->decode($this->request('POST', $path, json_encode($payload, JSON_THROW_ON_ERROR), ['Content-Type' => 'application/json'], $plane, $consumer ? 16777216 : null), $consumer, preserveObjectKinds: $preserveObjectKinds);
    }

    /**
     * @param  array<array-key, mixed>  $payload
     * @return array<array-key, mixed>
     */
    public function form(string $path, array $payload, string $plane = 'browser'): array
    {
        return $this->decode($this->request('POST', $path, http_build_query($payload, '', '&', PHP_QUERY_RFC3986), ['Content-Type' => 'application/x-www-form-urlencoded'], $plane));
    }

    /** @return array<array-key, mixed> */
    public function bearer(string $path, string $token): array
    {
        return $this->get($path, ['Authorization' => 'Bearer '.$token]);
    }

    /**
     * @param  array<array-key, mixed>  $payload
     * @return array<array-key, mixed>
     */
    public function sync(string $operation, #[\SensitiveParameter] array $payload): array
    {
        Contract::require(in_array($operation, ['profiles.read', 'profiles.list', 'profiles.import'], true), 'user_sync_operation_invalid', 422);

        return $this->decode($this->request('POST', '/api/consumer-sync/v1/'.$operation, json_encode($payload, JSON_THROW_ON_ERROR), ['Content-Type' => 'application/json'], 'browser', 16777216), false, true);
    }

    public function sendPsr(RequestInterface $request): ResponseInterface
    {
        $headers = [];
        foreach ($request->getHeaders() as $key => $values) {
            $headers[$key] = implode(', ', $values);
        }

        return $this->request($request->getMethod(), (string) $request->getUri(), (string) $request->getBody(), $headers);
    }

    /** @param array<array-key, string> $headers */
    private function request(string $method, string $path, #[\SensitiveParameter] ?string $body = null, array $headers = [], ?string $plane = null, ?int $maximumBytes = null): ResponseInterface
    {
        $origin = $this->config->origin();
        $url = str_starts_with($path, '/') && ! str_starts_with($path, '//') ? $origin.$path : $path;
        if (! str_starts_with($url, $origin.'/') || preg_match('/[\x00-\x20\x7f\\\\]/', $url) || parse_url($url, PHP_URL_FRAGMENT) !== null || parse_url($url, PHP_URL_USER) !== null) {
            throw new IdentityException('untrusted_endpoint');
        }
        try {
            $pending = $this->config instanceof ServiceTargetContext
                ? Http::withoutGlobalConfiguration(fn () => Http::createPendingRequest())
                : Http::createPendingRequest();
            $client = $pending->acceptJson()->withHeaders($headers)->timeout(5)->connectTimeout(3)->withoutRedirecting()->withOptions(['cookies' => false, 'verify' => $this->config->value('http.ca_bundle') ?: true, 'http_errors' => false]);
            if ($plane !== null) {
                $c = $this->config instanceof ServiceTargetContext ? ($plane === 'service' ? $this->config->credentials() : throw new IdentityException('invalid_credential_plane')) : $this->config->credentials($plane);
                $client = $client->withBasicAuth($c['id'], $c['secret']);
            }
            $result = $client->send($method, $url, $body === null ? [] : ['body' => $body]);
            if (strlen($result->body()) > ($maximumBytes ?? (int) $this->config->value('http.max_response_bytes', 131072))) {
                throw new IdentityException('response_too_large', 502);
            }
            if ($result->status() >= 300 && $result->status() < 400) {
                throw new IdentityException('redirect_refused', 502);
            }
            if ($result->status() === 429) {
                $retryHeader = $result->toPsrResponse()->hasHeader('Retry-After') ? 'Retry-After' : 'X-Retry-After';

                throw new IdentityException('rate_limited', 429, $this->retryAfter((string) $result->header($retryHeader)));
            }

            return new PsrResponse($result->status(), $result->toPsrResponse()->getHeaders(), $result->body());
        } catch (IdentityException $e) {
            throw $e;
        } catch (Throwable) {
            throw new IdentityException('transport_unavailable');
        }
    }

    /** @return array<array-key, mixed> */
    private function decode(ResponseInterface $response, bool $consumer = false, bool $sync = false, bool $preserveObjectKinds = false): array
    {
        if ($response->getStatusCode() >= 400) {
            $status = $response->getStatusCode() >= 500 ? 503 : $response->getStatusCode();
            $code = 'upstream_rejected';
            $retryAfter = null;
            if ($consumer) {
                try {
                    $body = json_decode((string) $response->getBody(), true, 16, JSON_THROW_ON_ERROR);
                    $candidate = is_array($body) && is_array($body['error'] ?? null) ? ($body['error']['code'] ?? null) : null;
                    if (is_string($candidate) && in_array($candidate, ['consumer_profile_field_denied', 'consumer_global_effect_acknowledgement_required', 'consumer_capability_denied', 'mfa_required', 'version_conflict', 'idempotency_conflict', 'operation_pending', 'context_changed', 'consumer_disabled', 'access_inactive', 'session_inactive', 'token_inactive', 'app_administration_denied', 'delegation_authority_required', 'delegation_unavailable', 'delegation_expired', 'rate_limited', 'operation_unavailable', 'consumer_resource_unavailable', 'validation_failed', 'invalid_cursor'], true)) {
                        $code = $candidate;
                    }
                } catch (Throwable) { /* Only public allowlisted error codes cross this boundary. */
                }
                $retryAfter = $this->retryAfter($response->getHeaderLine('Retry-After'));
            }
            if ($sync) {
                try {
                    $body = json_decode((string) $response->getBody(), true, 16, JSON_THROW_ON_ERROR);
                    $candidate = is_array($body) && is_array($body['error'] ?? null) ? ($body['error']['code'] ?? null) : null;
                    if (is_string($candidate) && in_array($candidate, ['consumer_import_email_conflict', 'consumer_import_password_unsupported', 'consumer_import_role_denied', 'consumer_import_metadata_denied', 'consumer_import_disabled', 'consumer_import_snapshot_unavailable', 'consumer_import_unavailable', 'consumer_sync_response_too_large'], true)) {
                        $code = $candidate;
                    }
                } catch (Throwable) { /* Public codes only; no upstream body or exception text escapes. */
                }
                if ($status === 400) {
                    try {
                        $body = json_decode((string) $response->getBody(), true, 16, JSON_THROW_ON_ERROR);
                        if (is_array($body) && is_array($body['error'] ?? null) && ($body['error']['code'] ?? null) === 'consumer_sync_cursor_invalid') {
                            $code = 'consumer_sync_cursor_invalid';
                        }
                    } catch (Throwable) { /* Only the exact public cursor rejection enables bounded restart. */
                    }
                }
                if ($status >= 500) {
                    $retryAfter = $this->retryAfter($response->getHeaderLine('Retry-After'));
                }
            }
            throw new IdentityException($code, $status, $retryAfter);
        }
        try {
            $json = json_decode((string) $response->getBody(), ! $preserveObjectKinds, 64, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new IdentityException('malformed_response', 502);
        }
        if ($preserveObjectKinds) {
            Contract::require($json instanceof \stdClass, 'malformed_response', 502);

            return (array) $json;
        }
        if (! is_array($json) || (array_is_list($json) && trim((string) $response->getBody()) !== '{}')) {
            throw new IdentityException('malformed_response', 502);
        }

        return $json;
    }

    private function retryAfter(string $value): ?int
    {
        if (preg_match('/^[0-9]{1,4}$/D', $value) !== 1) {
            return null;
        }
        $seconds = (int) $value;

        return $seconds > 0 && $seconds <= 3600 ? $seconds : null;
    }
}
