<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Services;

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Support\ServiceTargetContext;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * Fixed downstream bearer transport. Provider worker Basic credentials never enter it.
 *
 * @internal Use ServiceTokenManager's named target client for outbound calls.
 */
final readonly class ServiceTargetHttp
{
    public function __construct(private ServiceTargetContext $config) {}

    /** @param array<array-key, mixed> $options */
    public function request(string $relativePath, array $options = []): ResponseInterface
    {
        app(ExecutionPolicy::class)->assertOutboundAllowed();
        Contract::require(array_diff(array_keys($options), ['scopes', 'method', 'headers', 'body']) === [], 'invalid_service_request', 400);
        $url = $this->destination($relativePath);
        $method = $options['method'] ?? 'GET';
        $headers = $options['headers'] ?? [];
        $body = $options['body'] ?? null;
        Contract::require(is_string($method) && in_array($method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'], true)
            && ($body === null || (is_string($body) && strlen($body) <= 65536))
            && (! in_array($method, ['GET', 'HEAD'], true) || $body === null), 'invalid_service_request', 400);
        $this->headers($headers);
        $tokens = new ServiceTokenClient($this->config, new IdentityHttp($this->config));
        if (array_key_exists('scopes', $options)) {
            Contract::require(is_array($options['scopes']), 'service_scope_invalid', 400);
            $token = $tokens->token($options['scopes']);
        } else {
            $token = $tokens->token();
        }
        app(ExecutionPolicy::class)->assertOutboundAllowed();
        $maximum = min(1048576, $this->config->value('http.max_response_bytes', 131072));
        $started = microtime(true);
        try {
            // Capture an isolated pending request, restoring host globals before sending.
            $client = Http::withoutGlobalConfiguration(fn () => Http::createPendingRequest());
            $response = $client->withHeaders($headers)->withToken($token)->timeout(5)->connectTimeout(3)->withoutRedirecting()->withOptions([
                'cookies' => false,
                'verify' => $this->config->value('http.ca_bundle') ?: true,
                'http_errors' => false,
                'stream' => true,
                'read_timeout' => 5,
                'on_headers' => function (ResponseInterface $response) use ($maximum): void {
                    $length = $response->getHeaderLine('Content-Length');
                    Contract::require($length === '' || (ctype_digit($length) && (float) $length <= $maximum), 'response_too_large', 502);
                },
                'progress' => function ($total, $received) use ($maximum): void {
                    Contract::require($received <= $maximum, 'response_too_large', 502);
                },
            ])->send($method, $url, $body === null ? [] : ['body' => $body]);
            $stream = $response->toPsrResponse()->getBody();
            $bytes = '';
            try {
                Contract::require($response->status() < 300 || $response->status() >= 400, 'redirect_refused', 502);
                $effective = $response->effectiveUri();
                Contract::require($effective === null || (string) $effective === $url, 'untrusted_endpoint', 502);
                while (! $stream->eof()) {
                    Contract::require(microtime(true) - $started < 5, 'transport_unavailable', 503);
                    $chunk = $stream->read(min(8192, $maximum + 1 - strlen($bytes)));
                    Contract::require($chunk !== '' || $stream->eof(), 'transport_unavailable', 503);
                    $bytes .= $chunk;
                    Contract::require(strlen($bytes) <= $maximum, 'response_too_large', 502);
                }
            } finally {
                $stream->close();
            }
            Contract::require(microtime(true) - $started < 5, 'transport_unavailable', 503);

            return new Response($response->status(), $response->toPsrResponse()->getHeaders(), $bytes);
        } catch (IdentityException $error) {
            throw $error;
        } catch (Throwable) {
            throw new IdentityException('transport_unavailable');
        }
    }

    private function destination(string $path): string
    {
        // The trusted base is already validated by ServiceTargetContext. Treat it
        // as a directory whether or not configuration includes its trailing slash.
        Contract::require($path !== '' && strlen($path) <= 4096 && ! preg_match('/[\x00-\x20\x7f-\xff\\\\#]/', $path) && ! str_starts_with($path, '/'), 'invalid_service_destination', 400);
        $pathname = explode('?', $path, 2)[0];
        Contract::require($pathname !== '' && ! str_contains($pathname, ':') && ! str_contains($pathname, '//')
            && preg_match("#\\A[A-Za-z0-9._~!$&'()*+,;=@/-]+\\z#", $pathname) === 1
            && ! array_intersect(explode('/', $pathname), ['.', '..']), 'invalid_service_destination', 400);
        if (str_contains($path, '?')) {
            $query = explode('?', $path, 2)[1];
            Contract::require(! preg_match('/%(?![a-fA-F0-9]{2})/', $query), 'invalid_service_destination', 400);
        }

        try {
            $base = new Uri($this->config->baseUrl());
            $prefix = rtrim($base->getPath(), '/').'/';
            $destination = new Uri(rtrim((string) $base, '/').'/'.$path);
            Contract::require($destination->getScheme() === 'https' && $destination->getUserInfo() === ''
                && $destination->getAuthority() === $base->getAuthority()
                && $destination->getPath() === $prefix.$pathname && $destination->getFragment() === '', 'invalid_service_destination', 400);

            // Use the exact canonical URI for both the send and effective-URI check.
            return (string) $destination;
        } catch (Throwable) {
            throw new IdentityException('invalid_service_destination', 400);
        }
    }

    /** @phpstan-assert array<string, string> $headers */
    private function headers(mixed $headers): void
    {
        Contract::require(is_array($headers), 'invalid_service_request', 400);
        $bytes = 0;
        $seen = [];
        foreach ($headers as $name => $value) {
            Contract::require(is_string($name) && preg_match("/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/D", $name) === 1 && is_string($value) && ! preg_match('/[\x00-\x1f\x7f]/', $value), 'invalid_service_request', 400);
            $lower = strtolower($name);
            Contract::require(! in_array($lower, ['authorization', 'cookie', 'cookie2', 'host', 'origin', 'referer', 'connection', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'expect', 'forwarded', 'via'], true)
                && ! str_starts_with($lower, 'proxy-') && ! str_starts_with($lower, 'sec-') && ! str_starts_with($lower, 'x-forwarded-') && ! isset($seen[$lower]), 'invalid_service_request', 400);
            $seen[$lower] = true;
            $bytes += strlen($name) + strlen($value) + 4;
        }
        Contract::require($bytes <= 16384, 'invalid_service_request', 400);
    }
}
