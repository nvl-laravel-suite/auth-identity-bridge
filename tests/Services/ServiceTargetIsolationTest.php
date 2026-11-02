<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Services;

use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Services\ServiceTokenManager;
use IdentityPlatform\Laravel\Support\ServiceTargetRegistry;
use IdentityPlatform\Laravel\Tests\Support\NamedConfigurationFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

final class ServiceTargetIsolationTest extends TestCase
{
    use NamedConfigurationFixture;

    public function test_targets_issuers_and_rotated_credentials_are_independent(): void
    {
        $a = config('identity.service_targets.reports');
        $b = array_replace($a, ['application_id' => 'billing', 'client_id' => 'billing-worker', 'client_secret' => 'billing-secret', 'base_url' => 'https://billing.test/v1']);
        $c = array_replace($a, ['origin' => 'https://other-issuer.test']);
        $rotated = array_replace($a, ['client_secret' => 'rotated-secret']);
        $manager = new ServiceTokenManager(new ServiceTargetRegistry(['a' => $a, 'b' => $b, 'c' => $c, 'rotated' => $rotated], ['array']));
        $issued = 0;
        Http::fake(function ($request) use (&$issued) {
            return Http::response(str_ends_with($request->url(), '/revoke') ? '{}' : $this->response('synthetic-'.++$issued));
        });
        $tokens = [];
        foreach (['a', 'b', 'c', 'rotated'] as $name) {
            $tokens[$name] = $manager->target($name)->token();
        }
        self::assertCount(4, array_unique($tokens));
        $manager->target('rotated')->reject($tokens['a']);
        $manager->target('b')->revoke($tokens['a']);
        $manager->target('a')->revoke($tokens['a']);
        foreach (['b', 'c', 'rotated'] as $name) {
            self::assertSame($tokens[$name], $manager->target($name)->token());
        }
        self::assertNotSame($tokens['a'], $manager->target('a')->token());
        self::assertSame(5, $issued);
        Http::assertSent(fn ($r) => $r->url() === 'https://identity.test/api/service-auth/oauth2/token' && $r['resource'] === 'urn:identity-platform:application:billing' && $r->hasHeader('Authorization', 'Basic '.base64_encode('billing-worker:billing-secret')));
        Http::assertSent(fn ($r) => $r->url() === 'https://other-issuer.test/api/service-auth/oauth2/token' && $r['resource'] === 'urn:identity-platform:application:app-1');
    }

    public function test_normalized_scope_set_reuses_cache_and_explicit_empty_or_duplicates_refuse(): void
    {
        $this->configure(['identity.service_targets.reports.scopes' => ['documents.read', 'documents.write']]);
        Http::fake(['*' => Http::response($this->response('synthetic-set', ['scope' => 'documents.write documents.read']))]);
        $client = app(ServiceTokenManager::class)->target('reports');
        self::assertSame($client->token(['documents.write', 'documents.read']), $client->token(['documents.read', 'documents.write']));
        foreach ([[], ['documents.read', 'documents.read']] as $scopes) {
            try {
                $client->token($scopes);
                self::fail('Invalid scopes accepted');
            } catch (IdentityException $e) {
                self::assertSame('service_scope_invalid', $e->errorCode);
            }
        }
        Http::assertSentCount(1);
    }

    public function test_optional_absolute_expiry_can_only_shorten_request_start_lifetime(): void
    {
        $before = microtime(true);
        $expiry = time() + 30;
        Http::fakeSequence()->push($this->response('synthetic-cap', ['expires_at' => time() + 600]))->push($this->response('synthetic-short', ['expires_at' => $expiry]));
        app(ServiceTokenManager::class)->target('reports')->token();
        $entry = $this->entry();
        self::assertGreaterThanOrEqual($before, $entry['issued_at']);
        self::assertEqualsWithDelta($entry['issued_at'] + 300, $entry['expires_at'], 0.0001);
        Cache::flush();
        app(ServiceTokenManager::class)->target('reports')->token();
        self::assertSame($expiry, $this->entry()['expires_at']);
    }

    #[DataProvider('invalidExpires')]
    public function test_invalid_or_elapsed_optional_expiry_refuses(mixed $expires): void
    {
        Http::fake(['*' => Http::response($this->response('synthetic-expiry', ['expires_at' => $expires]))]);
        $this->expectException(IdentityException::class);
        app(ServiceTokenManager::class)->target('reports')->token();
    }

    public static function invalidExpires(): array
    {
        return [[1], [0], [-1], ['300'], [1.5], [null]];
    }

    public function test_exact_reuse_deadline_is_five_seconds_before_expiry(): void
    {
        Http::fakeSequence()->push($this->response('synthetic-old'))->push($this->response('synthetic-new'));
        $client = app(ServiceTokenManager::class)->target('reports');
        $client->token();
        foreach (array_keys(Cache::store('array')->getStore()->all()) as $key) {
            $entry = json_decode(Crypt::decryptString(Cache::get($key)), true);
            $entry['issued_at'] = microtime(true) - 100;
            $entry['expires_at'] = microtime(true) + 5;
            Cache::put($key, Crypt::encryptString(json_encode($entry)), 300);
        }
        self::assertSame('synthetic-new', $client->token());
        Http::assertSentCount(2);
    }

    #[DataProvider('outages')]
    public function test_provider_outage_never_tries_another_target_or_credential_family(int $status): void
    {
        Http::fake(['*' => Http::response(['error' => 'private'], $status)]);
        try {
            app(ServiceTokenManager::class)->target('reports')->token();
            self::fail('Outage accepted');
        } catch (IdentityException $e) {
            self::assertSame(503, $e->status);
            Http::assertSentCount(1);
            self::assertSame([], Cache::store('array')->getStore()->all());
        }
    }

    public static function outages(): array
    {
        return [[401], [403], [500], [503]];
    }

    #[DataProvider('delegatedOperations')]
    public function test_different_named_graph_cannot_escape_outer_delegation(string $operation, string $status): void
    {
        Http::fake(['*' => Http::response($this->response('synthetic-cached'))]);
        $client = app(ServiceTokenManager::class)->target('reports');
        $token = $client->token();
        $cacheBefore = Cache::store('array')->getStore()->all();
        $overlays = app(OverlayRepository::class);
        $overlays->save('outer-delegated', ['source_sid' => 'central-session', 'status' => $status, 'browser_binding' => str_repeat('b', 43), 'context_version' => 2, 'expires_at' => now()->addMinutes(5)]);
        $request = Request::create('https://consumer.test/');
        $session = new Store('outer_session', new ArraySessionHandler(120));
        $session->start();
        $session->put('identity.session', 'outer-delegated');
        $request->setLaravelSession($session);
        $this->bindRequest($request);
        $other = (new Identity($this->app, $this->registry($this->twoConsumers())))->consumer('two');
        $otherClient = $other->make(ServiceTokenManager::class)->target('reports');
        try {
            match ($operation) {
                'token' => $otherClient->token(),
                'reject' => $otherClient->reject($token),
                'revoke' => $otherClient->revoke($token),
                'request' => $otherClient->request('documents'),
            };
            self::fail('Outer delegation escaped');
        } catch (IdentityException $error) {
            self::assertSame('delegation_outbound_forbidden', $error->errorCode);
            self::assertSame(403, $error->status);
            self::assertSame($cacheBefore, Cache::store('array')->getStore()->all());
            Http::assertSentCount(1);
        }
    }

    public static function delegatedOperations(): array
    {
        $cases = [];
        foreach (['pending', 'active'] as $status) {
            foreach (['token', 'reject', 'revoke', 'request'] as $operation) {
                $cases[] = [$operation, $status];
            }
        }

        return $cases;
    }

    public function test_delegation_activated_during_issuance_prevents_publication_and_attachment(): void
    {
        $request = Request::create('https://consumer.test/');
        $session = new Store('outer_session', new ArraySessionHandler(120));
        $session->start();
        $session->put('identity.session', 'changed-during-request');
        $request->setLaravelSession($session);
        $this->bindRequest($request);
        Http::fake(function () {
            app(OverlayRepository::class)->save('changed-during-request', ['source_sid' => 'central-session', 'status' => 'active', 'browser_binding' => str_repeat('b', 43), 'context_version' => 2, 'expires_at' => now()->addMinutes(5)]);

            return Http::response($this->response('synthetic-no-publication'));
        });
        try {
            app(ServiceTokenManager::class)->target('reports')->request('documents');
            self::fail('New delegation allowed publication');
        } catch (IdentityException $error) {
            self::assertSame('delegation_outbound_forbidden', $error->errorCode);
            self::assertSame([], Cache::store('array')->getStore()->all());
            Http::assertSentCount(1);
        }
    }

    public function test_remote_revocation_failure_keeps_local_generation_and_does_not_retry(): void
    {
        Http::fakeSequence()->push($this->response('synthetic-retained'))->push(['error' => 'unavailable'], 503);
        $client = app(ServiceTokenManager::class)->target('reports');
        $token = $client->token();
        try {
            $client->revoke($token);
            self::fail('Revocation outage hidden');
        } catch (IdentityException $error) {
            self::assertSame(503, $error->status);
        }
        self::assertSame($token, $client->token());
        Http::assertSentCount(2);
    }

    public function test_concurrent_workers_reuse_one_real_file_cache_generation(): void
    {
        if (! function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is required for isolated process-lock verification');
        }
        $this->configure(['identity.service_targets.reports.cache_store' => 'identity_tests']);
        $directory = sys_get_temp_dir().'/identity-p7b-'.bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        file_put_contents($directory.'/issued', '0');
        Http::fake(function () use ($directory) {
            $counter = fopen($directory.'/issued', 'c+');
            flock($counter, LOCK_EX);
            $issued = (int) stream_get_contents($counter) + 1;
            ftruncate($counter, 0);
            rewind($counter);
            fwrite($counter, (string) $issued);
            fflush($counter);
            flock($counter, LOCK_UN);
            fclose($counter);
            usleep(200000);

            return Http::response($this->response('synthetic-concurrent-'.$issued));
        });
        $children = [];
        try {
            for ($i = 0; $i < 3; $i++) {
                $pid = pcntl_fork();
                self::assertNotSame(-1, $pid);
                if ($pid === 0) {
                    try {
                        $token = app(ServiceTokenManager::class)->target('reports')->token();
                        file_put_contents($directory.'/result-'.$i, hash('sha256', $token));
                        exit(0);
                    } catch (\Throwable) {
                        exit(17);
                    }
                }
                $children[] = $pid;
            }
            foreach ($children as $pid) {
                pcntl_waitpid($pid, $status);
                self::assertTrue(pcntl_wifexited($status));
                self::assertSame(0, pcntl_wexitstatus($status));
            }
            self::assertSame('1', file_get_contents($directory.'/issued'));
            foreach (range(0, 2) as $i) {
                self::assertSame(hash('sha256', 'synthetic-concurrent-1'), file_get_contents($directory.'/result-'.$i));
            }
        } finally {
            foreach (glob($directory.'/*') as $path) {
                unlink($path);
            }
            rmdir($directory);
        }
    }

    private function entry(): array
    {
        $keys = array_values(array_filter(array_keys(Cache::store('array')->getStore()->all()), fn ($key) => str_contains($key, ':entry:')));

        return json_decode(Crypt::decryptString(Cache::get($keys[0])), true);
    }

    private function response(string $token, array $extra = []): array
    {
        return array_replace(['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => 'documents.read'], $extra);
    }
}
