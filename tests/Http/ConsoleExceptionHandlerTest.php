<?php

namespace IdentityPlatform\Laravel\Tests\Http;

use Error;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Contracts\Debug\ExceptionHandler as ExceptionHandlerContract;
use Illuminate\Contracts\Debug\ShouldntReport;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\Request;
use NunoMaduro\Collision\Adapters\Laravel\ExceptionHandler as CollisionHandler;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class ConsoleExceptionHandlerTest extends TestCase
{
    private function collision(Handler $underlying): ExceptionHandlerContract
    {
        $decorator = new CollisionHandler($this->app, $underlying);
        try {
            $this->app->bind(ExceptionHandlerContract::class, fn () => $decorator);

            return $this->app->make(ExceptionHandlerContract::class);
        } catch (Error $error) {
            $this->fail('Installed console decorator must resolve through package handler callbacks: '.$error->getMessage());
        }
    }

    public function test_identity_failure_uses_laravel_reporting_marker_without_handler_configuration(): void
    {
        $error = new IdentityException('context_changed', 409);
        $this->assertInstanceOf(ShouldntReport::class, $error);
        $this->assertFalse((new Handler($this->app))->shouldReport($error));
    }

    public function test_real_collision_decorator_resolves_and_keeps_package_and_host_renderers(): void
    {
        $underlying = new Handler($this->app);
        $underlying->renderable(function (IdentityException $error): ?Response {
            return $error->errorCode === 'host_presentation' ? response('Host error presentation', 403) : null;
        });
        $handler = $this->collision($underlying);
        $this->assertInstanceOf(CollisionHandler::class, $handler);
        $response = $handler->render(Request::create('/synthetic-console-error'), new IdentityException('context_changed', 409));
        $this->assertSame(409, $response->getStatusCode());
        $this->assertSame(['error' => 'context_changed'], json_decode($response->getContent(), true));
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $host = $handler->render(Request::create('/synthetic-host-error'), new IdentityException('host_presentation', 403));
        $this->assertSame('Host error presentation', $host->getContent());
    }

    public function test_real_collision_decorator_suppresses_only_expected_identity_reporting(): void
    {
        $reported = [];
        $underlying = new Handler($this->app);
        $underlying->reportable(function (Throwable $error) use (&$reported): bool {
            $reported[] = $error::class;

            return false;
        });
        $handler = $this->collision($underlying);
        $expected = new IdentityException('access_denied', 403);
        $unrelated = new RuntimeException('Synthetic unrelated failure');
        $this->assertFalse($handler->shouldReport($expected));
        $this->assertTrue($handler->shouldReport($unrelated));
        $handler->report($expected);
        $handler->report($unrelated);
        $this->assertSame([RuntimeException::class], $reported);
    }
}
