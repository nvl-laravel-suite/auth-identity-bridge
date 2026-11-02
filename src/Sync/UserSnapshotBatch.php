<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Support\IdentityConfig;

final readonly class UserSnapshotBatch
{
    private function __construct(public string $bindingHash, public int $policyVersion, public array $profiles, public ?string $nextCursor) {}

    public static function validate(array $data, IdentityConfig $config, ?array $requested = null): self
    {
        Contract::require(Contract::keys($data, ['contract', 'issuer', 'applicationId', 'clientId', 'policyVersion', 'profiles', 'nextCursor'])
            && $data['contract'] === 'platform-consumer-sync.v1' && $data['issuer'] === $config->issuer()
            && $data['applicationId'] === $config->applicationId() && $data['clientId'] === $config->clientId()
            && Contract::positive($data['policyVersion']) && is_array($data['profiles']) && array_is_list($data['profiles']) && count($data['profiles']) <= 100
            && ($data['nextCursor'] === null || self::cursor($data['nextCursor'])), 'invalid_user_snapshot', 502);
        $profiles = [];
        $seen = [];
        foreach ($data['profiles'] as $entry) {
            Contract::require(is_array($entry), 'invalid_user_snapshot', 502);
            $snapshot = UserSnapshot::validate($entry, $data['policyVersion'], $config);
            Contract::require(! isset($seen[$snapshot->subject]) && ($requested === null || in_array($snapshot->subject, $requested, true)), 'invalid_user_snapshot', 502);
            $seen[$snapshot->subject] = true;
            $profiles[] = $snapshot;
        }

        return new self($config->bindingHash(), $data['policyVersion'], $profiles, $data['nextCursor']);
    }

    public static function cursor(mixed $cursor): bool
    {
        return is_string($cursor) && $cursor !== '' && strlen($cursor) <= 4096 && mb_check_encoding($cursor, 'UTF-8') && ! preg_match('/[\x00-\x1f\x7f]/', $cursor);
    }
}
