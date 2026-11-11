<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

use Closure;
use IdentityPlatform\Laravel\Authorization\AuthorizationClient;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Oidc\OidcClient;
use IdentityPlatform\Laravel\Repositories\LoginRepository;
use IdentityPlatform\Laravel\Services\ResourceVerifier;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

/** Stack traces retain call arguments; credentials must not be readable from them. */
final class SensitiveArgumentsTest extends TestCase
{
    private const SECRET = 'synthetic-credential-that-must-not-be-traced';

    #[DataProvider('credentialBoundaries')]
    public function test_credentials_are_absent_from_failure_stack_traces(Closure $call): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');
        Http::fake(['*' => Http::response(['error' => 'unavailable'], 503)]);
        try {
            $call();
            self::fail('The failing boundary succeeded');
        } catch (IdentityException $error) {
            self::assertStringNotContainsString(self::SECRET, self::arguments($error->getTrace()));
        } finally {
            ini_set('zend.exception_ignore_args', (string) $previous);
        }
    }

    /** @return array<string, array{Closure(): mixed}> */
    public static function credentialBoundaries(): array
    {
        return [
            'authorization contexts' => [static fn () => app(AuthorizationClient::class)->contexts(self::SECRET, 'subject', 'sid')],
            'authorization snapshot' => [static fn () => app(AuthorizationClient::class)->snapshot(self::SECRET, 'subject', 'sid')],
            'resource credential' => [static fn () => app(ResourceVerifier::class)->verify('service_token', self::SECRET)],
            'human access token' => [static fn () => app(ResourceVerifier::class)->verify('human_token', self::SECRET)],
            'refresh token' => [static fn () => app(OidcClient::class)->refresh(['refresh_token' => self::SECRET])],
            'authorization code' => [static fn () => app(OidcClient::class)->exchange(['code' => self::SECRET, 'state' => 'state'], ['state' => 'state', 'nonce' => 'nonce', 'verifier' => str_repeat('v', 43), 'resource' => false])],
            'userinfo access token' => [static fn () => app(OidcClient::class)->userInfo(self::SECRET, 'subject')],
            'bearer transport' => [static fn () => app(IdentityHttp::class)->bearer('/api/auth/oauth2/userinfo', self::SECRET)],
            'form transport' => [static fn () => app(IdentityHttp::class)->form('/api/auth/oauth2/revoke', ['token' => self::SECRET])],
            'delegated report capability' => [static fn () => app(ConsumerClient::class)->report(['receiptId' => 'receipt-1', 'reportingCapability' => self::SECRET, 'commandDigest' => 'digest'], 'committed')],
            'consumer operation input' => [static fn () => app(ConsumerClient::class)->call(Request::create('https://consumer.test/delegation', 'POST'), 'delegation.redeem', ['code' => self::SECRET])],
            'login state' => [static fn () => app(LoginRepository::class)->consume(self::SECRET, 'browser', 'login')],
        ];
    }

    /** @param array<array-key, mixed> $trace */
    private static function arguments(array $trace): string
    {
        $found = [];
        array_walk_recursive($trace, function (mixed $value) use (&$found): void {
            if (is_string($value)) {
                $found[] = $value;
            }
        });

        return implode("\n", $found);
    }
}
