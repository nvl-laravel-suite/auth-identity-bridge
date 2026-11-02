<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Sync\ImportedPasswordHash;
use IdentityPlatform\Laravel\Sync\UserImportClient;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

class ImportPreflightTest extends TestCase
{
    public function test_unsupported_hash_is_rejected_before_transport(): void
    {
        $this->configure(['identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.import_enabled' => true]);
        Http::fake(['*' => Http::response(['contract' => 'platform-consumer-sync-import.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'mappings' => [['sourceUserId' => 'row-1', 'subject' => 'subject-1', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()]]])]);
        try {
            app(UserImportClient::class)->import([['sourceUserId' => 'row-1', 'name' => 'Example', 'email' => 'person@example.test', 'emailVerified' => true, 'passwordHash' => str_repeat('x', 60)]]);
            $this->fail('Unsupported hash reached the provider');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_hash_unsupported', $error->errorCode);
        }
        Http::assertNothingSent();
    }

    public static function hashFormats(): array
    {
        $salt = rtrim(base64_encode(str_repeat('s', 16)), '=');
        $digest = rtrim(base64_encode(str_repeat('d', 32)), '=');

        return [
            ['$2a$04$'.str_repeat('a', 53), true], ['$2b$14$'.str_repeat('a', 53), true], ['$2y$15$'.str_repeat('a', 53), false],
            ['$2y$03$'.str_repeat('a', 53), false], ['$2y$10$'.str_repeat('a', 54), false],
            ['$argon2id$v=19$m=65536,t=6,p=4$'.$salt.'$'.$digest, true],
            ['$argon2id$v=19$m=65537,t=6,p=4$'.$salt.'$'.$digest, false],
            ['$argon2id$v=19$m=32,t=7,p=4$'.$salt.'$'.$digest, false],
            ['$argon2id$v=19$m=32,t=6,p=5$'.$salt.'$'.$digest, false],
            ['$argon2id$v=19$m=7,t=1,p=1$'.$salt.'$'.$digest, false],
            ['$argon2id$v=19$m=32,t=1,p=1$cw$'.$digest, false],
            ['$argon2id$v=19$m=32,t=1,p=1$'.$salt.'$ZA', false],
            ['$argon2i$v=19$m=32,t=1,p=1$'.$salt.'$'.$digest, false],
            [str_repeat('x', 513), false],
        ];
    }

    #[DataProvider('hashFormats')]
    public function test_supported_hash_bounds_match_public_contract(string $hash, bool $expected): void
    {
        $this->assertSame($expected, ImportedPasswordHash::supported($hash));
    }
}
