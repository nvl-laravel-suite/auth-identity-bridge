<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Support\IdentityConfig;

final readonly class UserImportResult
{
    /** @param list<UserImportMapping> $mappings */
    private function __construct(public string $bindingHash, public string $issuer, public string $applicationId, public string $clientId, public int $policyVersion, public array $mappings) {}

    public static function validate(array $data, IdentityConfig $config, array $requestedSources): self
    {
        Contract::require(Contract::keys($data, ['contract', 'issuer', 'applicationId', 'clientId', 'policyVersion', 'mappings'])
            && $data['contract'] === 'platform-consumer-sync-import.v1' && $data['issuer'] === $config->issuer()
            && $data['applicationId'] === $config->applicationId() && $data['clientId'] === $config->clientId()
            && Contract::positive($data['policyVersion']) && is_array($data['mappings']) && array_is_list($data['mappings'])
            && count($data['mappings']) > 0 && count($data['mappings']) <= 100
            && array_is_list($requestedSources) && count($requestedSources) === count($data['mappings']), 'invalid_user_import_result', 502);
        $mappings = [];
        $sources = [];
        $subjects = [];
        foreach ($data['mappings'] as $entry) {
            Contract::require(is_array($entry) && Contract::keys($entry, ['sourceUserId', 'subject', 'version', 'state', 'profile'])
                && Contract::identifier($entry['sourceUserId']) && in_array($entry['sourceUserId'], $requestedSources, true)
                && ! in_array($entry['sourceUserId'], $sources, true), 'invalid_user_import_result', 502);
            $source = $entry['sourceUserId'];
            unset($entry['sourceUserId']);
            $snapshot = UserSnapshot::validate($entry, $data['policyVersion'], $config);
            Contract::require(! in_array($snapshot->subject, $subjects, true), 'invalid_user_import_result', 502);
            $sources[] = $source;
            $subjects[] = $snapshot->subject;
            $mappings[] = new UserImportMapping($source, $snapshot);
        }

        return new self($config->bindingHash(), $data['issuer'], $data['applicationId'], $data['clientId'], $data['policyVersion'], $mappings);
    }
}
