<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel;

use IdentityPlatform\Laravel\Auth\BrowserLifecycle;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;

/** Explicit operation factory. Never stores an ambient selected consumer.
 * @api
 */
final readonly class Identity
{
    public function __construct(private Container $app, private ConsumerRegistry $registry) {}

    /** Current trusted HTTP graph only; jobs must select an explicit consumer. */
    public function browser(): BrowserLifecycle
    {
        $graph = $this->app->make(ConsumerGraph::class);
        $request = $graph->make(Request::class);
        if (! $request->hasSession() || $request->getSchemeAndHttpHost() !== $graph->context->appOrigin()) {
            throw new IdentityException('browser_request_required', 401);
        }

        return $graph->make(BrowserLifecycle::class);
    }

    public function consumer(string $name, ?Request $request = null): ConsumerGraph
    {
        return new ConsumerGraph($this->app, $this->registry->get($name), $request ?? new Request);
    }

    public function byBinding(string $binding): ConsumerGraph
    {
        return $this->consumer($this->registry->byBinding($binding)->name());
    }
}
