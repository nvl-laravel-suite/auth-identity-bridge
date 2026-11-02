<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Profiles;

use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/** Account-owner service; management and delegated writes use their explicit operation policy. */
class LocalProfileManager
{
    public function __construct(private ConsumerGraph $graph, private IdentityAccess $access, private LocalProfileRepository $profiles, private OrdinaryActionRunner $actions) {}

    public function read(Authenticatable $owner): LocalProfile
    {
        $this->access->assertOwner($owner);

        return $this->profiles->read($owner);
    }

    /**
     * @param  array<string, mixed>  $fields
     */
    public function update(Authenticatable $owner, int $expectedVersion, array $fields): LocalProfile
    {
        return $this->actions->run($this->graph->make(Request::class), fn () => $this->profiles->lock($owner), function () use ($owner, $expectedVersion, $fields): LocalProfile {
            $this->access->assertOwner($owner);

            return $this->profiles->update($owner, $expectedVersion, $fields);
        });
    }
}
