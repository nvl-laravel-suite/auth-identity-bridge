<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

require_once __DIR__.'/NamedConfigurationFixture.php';

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\ServiceTargetRegistry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ServiceTargetRegistryTest extends TestCase
{
    use NamedConfigurationFixture;

    protected function setUp(): void
    {
        $this->assertTrue(class_exists(ConsumerRegistry::class), 'Immutable named registry is missing');
    }

    public function test_target_issuer_audience_credentials_and_destination_are_independent_of_browser(): void
    {
        $registry = $this->registry();
        $target = $registry->serviceTargets()->get('reports');
        $this->assertSame('https://worker-issuer.test/api/service-auth', $target->issuer());
        $this->assertSame('reporting-app', $target->applicationId());
        $this->assertSame('reports-worker', $target->credentials()['id']);
        $this->assertSame('https://reports.test/api', $target->baseUrl());
        $this->assertSame(['reports.read', 'reports.write'], $target->scopes());
        $this->assertStringNotContainsString('synthetic-worker-secret', json_encode($target, JSON_THROW_ON_ERROR));
        $this->expectException(\LogicException::class);
        serialize($target);
    }

    public function test_unknown_target_never_falls_back_to_browser_or_default(): void
    {
        $this->expectExceptionObject(new IdentityException('unknown_service_target'));
        $this->registry()->serviceTargets()->get('one');
    }

    public function test_worker_registry_can_be_built_without_any_browser_definition(): void
    {
        $registry = new ServiceTargetRegistry(['reports' => $this->target()], ['shared']);
        $this->assertSame('reports-worker', $registry->get('reports')->credentials()['id']);
    }

    public function test_full_canonical_root_accepts_service_only_without_a_default_consumer(): void
    {
        $definition = $this->definition();
        $definition['consumers'] = [];
        $definition['default_consumer'] = null;
        $this->assertSame('reports-worker', $this->registry($definition)->serviceTargets()->get('reports')->credentials()['id']);
        $this->expectExceptionObject(new IdentityException('unknown_consumer'));
        $this->registry($definition)->get('one');
    }

    #[DataProvider('invalidTargets')]
    public function test_target_requires_complete_fixed_worker_configuration(string $key, mixed $value): void
    {
        $definition = $this->definition();
        $definition['service_targets']['reports'][$key] = $value;
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public static function invalidTargets(): array
    {
        return [['client_secret', null], ['client_id', ''], ['origin', 'http://worker.test'], ['base_url', 'https://user:pass@reports.test/api'], ['base_url', 'https://reports.test/api?redirect=1'], ['base_url', 'https://reports.test/a/../api'], ['application_id', ''], ['scopes', []], ['scopes', ['openid']], ['scopes', ['reports.read', 'reports.read']], ['cache_store', 'missing'], ['unknown', true], ['application_id', str_repeat('a', 129)], ['scopes', ['UPPERCASE']], ['scopes', array_map(fn (int $index): string => 'reports.item'.$index, range(1, 251))]];
    }
}
