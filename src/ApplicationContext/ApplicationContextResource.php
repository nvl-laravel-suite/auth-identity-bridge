<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\ApplicationContext;

use Carbon\CarbonImmutable;
use IdentityPlatform\Laravel\Exceptions\IdentityException;

/** Safe host facts only. localVersion covers the relevant resource/membership revision. */
final readonly class ApplicationContextResource
{
    public function __construct(public string $resourceId, public string $label, public string $localVersion, public CarbonImmutable $expiresAt)
    {
        foreach ([$resourceId, $label, $localVersion] as $value) {
            if ($value === '' || strlen($value) > 255 || preg_match('/[\x00-\x1F\x7F]/', $value)) {
                throw new IdentityException('application_context_invalid', 422);
            }
        }
        if (! $expiresAt->isFuture()) {
            throw new IdentityException('application_context_unavailable', 403);
        }
    }
}
