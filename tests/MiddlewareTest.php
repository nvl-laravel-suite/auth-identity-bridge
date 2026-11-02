<?php

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Http\Middleware\BrowserSafety;
use Illuminate\Http\Request;

class MiddlewareTest extends TestCase
{
    public function test_writes_require_exact_origin_and_duplicate_session_cookie_is_rejected(): void
    {
        $middleware = app(BrowserSafety::class);
        foreach ([['HTTP_ORIGIN' => 'https://evil.test'], []] as $headers) {
            $request = Request::create('https://consumer.test/action', 'POST', [], [], [], $headers);
            $response = $middleware->handle($request, fn () => response('unsafe'));
            $this->assertSame(403, $response->getStatusCode());
        }
        $this->configure(['session.cookie' => 'consumer']);
        $request = Request::create('https://consumer.test/', 'GET', [], [], [], ['HTTP_COOKIE' => 'consumer=a; consumer=b']);
        $this->assertSame(400, $middleware->handle($request, fn () => response('unsafe'))->getStatusCode());
    }

    public function test_safe_responses_are_not_cached(): void
    {
        $response = app(BrowserSafety::class)->handle(Request::create('https://consumer.test/'), fn () => response('ok'));
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $this->assertSame('strict-origin', $response->headers->get('Referrer-Policy'));
    }
}
