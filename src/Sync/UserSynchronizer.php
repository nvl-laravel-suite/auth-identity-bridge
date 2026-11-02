<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;

/** JIT projection of verified UserInfo; absent claims are not deletion authority. */
class UserSynchronizer
{
    public function __construct(private ConsumerGraph $graph, private IdentityConfig $config, private UserProjectionRepository $repository) {}

    public function sync(array $verifiedUserinfo): IdentityUser
    {
        $subject = $verifiedUserinfo['sub'] ?? null;
        if (! is_string($subject) || $subject === '' || mb_strlen($subject) > 255 ||
            ! mb_check_encoding($subject, 'UTF-8') || preg_match('/[\x00-\x1f\x7f]/', $subject)) {
            throw new IdentityException('userinfo_invalid', 502);
        }
        $profile = [];
        foreach (['name', 'email', 'picture'] as $claim) {
            if (array_key_exists($claim, $verifiedUserinfo)) {
                $value = $verifiedUserinfo[$claim];
                if ($value !== null && (! is_string($value) || ! mb_check_encoding($value, 'UTF-8') ||
                    str_contains($value, "\0") || mb_strlen($value) > ($claim === 'picture' ? 8192 : 255))) {
                    throw new IdentityException('userinfo_invalid', 502);
                }
                $profile[$claim] = $value;
            }
        }
        if (array_key_exists('email_verified', $verifiedUserinfo)) {
            if (! is_bool($verifiedUserinfo['email_verified'])) {
                throw new IdentityException('userinfo_invalid', 502);
            }
            $profile['email_verified'] = $verifiedUserinfo['email_verified'];
        }

        return (new IdentityUser)->getConnection()->transaction(function () use ($subject, $profile): IdentityUser {
            [$user, $created] = $this->repository->synchronize($this->config->issuer(), $subject, $profile);
            if ($this->config->value('sync.enabled', false) === true) {
                $this->graph->make(UserSyncWorkRepository::class)->register($subject);
            }
            ProfileSynchronized::dispatch($user, $created);

            return $user;
        });
    }
}
