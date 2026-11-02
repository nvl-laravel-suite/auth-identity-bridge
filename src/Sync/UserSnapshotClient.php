<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Users\NativeMappingDefinition;

class UserSnapshotClient
{
    public function __construct(private IdentityConfig $config, private IdentityHttp $http) {}

    /** @param array<array-key, mixed> $subjects */
    public function read(array $subjects): UserSnapshotBatch
    {
        $this->enabled();
        Contract::require(array_is_list($subjects) && count($subjects) > 0 && count($subjects) <= 100, 'user_sync_subjects_invalid', 422);
        $validatedSubjects = [];
        foreach ($subjects as $subject) {
            Contract::require(Contract::identifier($subject), 'user_sync_subjects_invalid', 422);
            $validatedSubjects[] = $subject;
        }

        Contract::require(count(array_unique($validatedSubjects)) === count($subjects), 'user_sync_subjects_invalid', 422);

        return UserSnapshotBatch::validate($this->http->sync('profiles.read', ['subjects' => $subjects]), $this->config, $subjects);
    }

    public function listing(?string $cursor = null, int $limit = 100): UserSnapshotBatch
    {
        $this->enabled();
        Contract::require($limit >= 1 && $limit <= 100 && ($cursor === null || UserSnapshotBatch::cursor($cursor)), 'user_sync_cursor_invalid', 422);

        return UserSnapshotBatch::validate($this->http->sync('profiles.list', array_filter(['cursor' => $cursor, 'limit' => $limit], fn ($value) => $value !== null)), $this->config);
    }

    private function enabled(): void
    {
        Contract::require($this->config->value('sync.enabled', false) === true, 'user_sync_disabled', 404);
        app(ExecutionPolicy::class)->assertOutboundAllowed();
        $model = $this->config->value('users.model');
        if ($model !== null) {
            $native = new $model;
            (new NativeMappingDefinition($this->config->value('users'), $native))->preflight($native);
        }

    }
}
