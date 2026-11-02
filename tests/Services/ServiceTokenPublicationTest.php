<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Services;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Services\ServiceTokenManager;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

final class PublicationStore extends ArrayStore
{
    public ?string $failure = null;

    public int $writes = 0;

    public function put($key, $value, $seconds)
    {
        $this->writes++;
        $index = str_contains($key, ':index:');
        if (($index && $this->failure === 'index-false') || (! $index && $this->failure === 'entry-false')) {
            return false;
        }
        if ($index && $this->failure === 'index-throw') {
            throw new RuntimeException('private cache diagnostic');
        }
        if (($index && $this->failure === 'index-after') || (! $index && $this->failure === 'entry-after')) {
            parent::put($key, $value, $seconds);
            throw new RuntimeException('private ambiguous cache diagnostic');
        }

        return parent::put($key, $value, $seconds);
    }
}

final class ServiceTokenPublicationTest extends TestCase
{
    private PublicationStore $store;

    protected function setUp(): void
    {
        parent::setUp();
        $this->store = new PublicationStore;
        $store = $this->store;
        Cache::extend('publication-test', fn () => Cache::repository($store));
        config(['cache.stores.publication-test' => ['driver' => 'publication-test']]);
        $this->configure(['identity.service_targets.reports.cache_store' => 'publication-test']);
        Http::preventStrayRequests();
    }

    #[DataProvider('publicationFailures')]
    public function test_failure_never_publishes_an_unindexed_reusable_token_and_recovery_remains_revocable(string $failure, bool $committedToken): void
    {
        $issued = 0;
        Http::fake(function ($request) use (&$issued) {
            if (str_ends_with($request->url(), '/revoke')) {
                return Http::response('{}');
            }

            return Http::response($this->response('synthetic-'.++$issued));
        });
        $client = app(ServiceTokenManager::class)->target('reports');
        $this->store->failure = $failure;
        try {
            $client->token();
            self::fail('Cache write failure was hidden');
        } catch (IdentityException $error) {
            self::assertContains($error->errorCode, ['service_cache_unavailable', 'service_token_unavailable']);
            self::assertNull($error->getPrevious());
        }
        $entries = $this->keys(':entry:');
        self::assertCount($committedToken ? 1 : 0, $entries);
        foreach ($entries as $key) {
            $entry = json_decode(Crypt::decryptString($this->store->get($key)), true);
            self::assertCount(1, $this->keys(':index:'));
            $index = json_decode(Crypt::decryptString($this->store->get($this->keys(':index:')[0])), true);
            self::assertSame($entry['generation'], $index['generation']);
            self::assertArrayNotHasKey('token', $index);
        }
        $this->store->failure = null;
        $recovered = $client->token();
        self::assertSame($committedToken ? 'synthetic-1' : 'synthetic-2', $recovered);
        $client->revoke($recovered);
        self::assertNotSame($recovered, $client->token());
        self::assertSame($committedToken ? 2 : 3, $issued);
    }

    public static function publicationFailures(): array
    {
        return [['index-false', false], ['index-throw', false], ['index-after', false], ['entry-false', false], ['entry-after', true]];
    }

    public function test_index_encryption_failure_does_not_reach_storage(): void
    {
        Http::fake(['*' => Http::response($this->response('synthetic-seal'))]);
        $encrypter = Crypt::getFacadeRoot();
        Crypt::shouldReceive('encryptString')->once()->andThrow(new RuntimeException('private encryption failure'));
        try {
            app(ServiceTokenManager::class)->target('reports')->token();
            self::fail('Encryption failure hidden');
        } catch (IdentityException $error) {
            self::assertSame('service_token_unavailable', $error->errorCode);
            self::assertSame(0, $this->store->writes);
        } finally {
            Crypt::swap($encrypter);
        }
    }

    public function test_all_stored_values_are_encrypted_and_index_has_no_plaintext_token(): void
    {
        Http::fake(['*' => Http::response($this->response('synthetic-private-token'))]);
        app(ServiceTokenManager::class)->target('reports')->token();
        self::assertCount(2, $this->store->all());
        foreach (array_keys($this->store->all()) as $key) {
            $ciphertext = $this->store->get($key);
            self::assertStringNotContainsString('synthetic-private-token', $key.$ciphertext);
            $record = json_decode(Crypt::decryptString($ciphertext), true);
            if (str_contains($key, ':index:')) {
                self::assertArrayNotHasKey('token', $record);
                self::assertSame(hash('sha256', 'synthetic-private-token'), $record['digest']);
            }
        }
    }

    public function test_missing_or_corrupt_index_cannot_make_a_token_reusable(): void
    {
        Http::fakeSequence()->push($this->response('synthetic-1'))->push($this->response('synthetic-2'))->push($this->response('synthetic-3'));
        $client = app(ServiceTokenManager::class)->target('reports');
        $client->token();
        $this->store->forget($this->keys(':index:')[0]);
        self::assertSame('synthetic-2', $client->token());
        $this->store->put($this->keys(':index:')[0], 'corrupt', 300);
        self::assertSame('synthetic-3', $client->token());
        Http::assertSentCount(3);
    }

    public function test_swapped_index_and_entry_cannot_authorize_cache_reuse(): void
    {
        Http::fakeSequence()->push($this->response('synthetic-1'))->push($this->response('synthetic-2'));
        $client = app(ServiceTokenManager::class)->target('reports');
        $client->token();
        $this->store->put($this->keys(':index:')[0], $this->store->get($this->keys(':entry:')[0]), 300);
        self::assertSame('synthetic-2', $client->token());
    }

    public function test_delayed_revocation_with_retained_old_index_cannot_remove_successor(): void
    {
        $client = app(ServiceTokenManager::class)->target('reports');
        $issued = 0;
        $new = null;
        Http::fake(function ($request) use ($client, &$issued, &$new) {
            if (str_ends_with($request->url(), '/revoke')) {
                $oldIndex = $this->keys(':index:')[0];
                $saved = $this->store->get($oldIndex);
                $client->reject('synthetic-1');
                $new = $client->token();
                // Simulate a retained predecessor index after an interrupted cleanup.
                $this->store->put($oldIndex, $saved, 300);

                return Http::response('{}');
            }

            return Http::response($this->response('synthetic-'.++$issued));
        });
        $old = $client->token();
        $client->revoke($old);
        self::assertSame($new, $client->token());
        self::assertSame(2, $issued);
    }

    private function keys(string $kind): array
    {
        return array_values(array_filter(array_keys($this->store->all()), fn ($key) => str_contains($key, $kind)));
    }

    private function response(string $token): array
    {
        return ['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => 'documents.read'];
    }
}
