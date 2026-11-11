<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Http;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Response;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

/** The configured response limit stops the transfer; it is not only checked after buffering. */
final class ProviderResponseLimitTest extends TestCase
{
    #[DataProvider('limits')]
    public function test_transfer_is_refused_as_soon_as_it_exceeds_the_response_limit(string $path, int $limit): void
    {
        $options = [];
        Http::fake(function ($request, array $sent) use (&$options) {
            $options = $sent;

            return Http::response('{}');
        });
        app(IdentityHttp::class)->json($path, []);

        self::assertIsCallable($options['on_headers'] ?? null);
        self::assertIsCallable($options['progress'] ?? null);
        $options['on_headers'](new Response(200, ['Content-Length' => (string) $limit]));
        $options['on_headers'](new Response(200));
        $options['progress'](0, $limit, 0, 0);
        foreach ([fn () => $options['on_headers'](new Response(200, ['Content-Length' => (string) ($limit + 1)])),
            fn () => $options['on_headers'](new Response(200, ['Content-Length' => 'not-a-length'])),
            fn () => $options['progress'](0, $limit + 1, 0, 0)] as $exceed) {
            try {
                $exceed();
                self::fail('An oversized provider response was not refused during transfer');
            } catch (IdentityException $error) {
                self::assertSame('response_too_large', $error->errorCode);
                self::assertSame(502, $error->status);
            }
        }
    }

    public function test_declared_oversize_keeps_its_public_refusal_when_the_client_wraps_it(): void
    {
        Http::fake(function ($request, array $options) {
            try {
                $options['on_headers'](new Response(200, ['Content-Length' => '131073']));
            } catch (Throwable $refusal) {
                throw new RequestException('An error was encountered during the on_headers event', $request->toPsrRequest(), null, $refusal);
            }

            return Http::response('{}');
        });

        $this->expectExceptionObject(new IdentityException('response_too_large', 502));
        app(IdentityHttp::class)->json('/api/authorization/contexts', []);
    }

    /** @return array<string, array{string, int}> */
    public static function limits(): array
    {
        return [
            'configured default' => ['/api/authorization/contexts', 131072],
            'consumer management' => ['/api/consumer/v1/self/read', 16777216],
        ];
    }
}
