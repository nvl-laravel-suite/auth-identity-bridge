<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\ApplicationContext;

/** Host eligibility is routing scope, never a permission grant. */
interface ApplicationContextProvider
{
    /** @return iterable<ApplicationContextResource> Only currently eligible, safe choices. */
    public function choices(ApplicationContextScope $scope): iterable;

    /**
     * Requery current resource/membership facts; null means ineligible or missing.
     * forUpdate runs in the consumer transaction: lock every fact whose change
     * could revoke eligibility, using the host's documented consistent lock order.
     * The caller must already hold its domain resource locks before assertEligible.
     */
    public function resolve(ApplicationContextScope $scope, string $resourceId, bool $forUpdate): ?ApplicationContextResource;
}
