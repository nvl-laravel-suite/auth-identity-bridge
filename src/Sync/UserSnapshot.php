<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\SharedProfile;

final readonly class UserSnapshot
{
    private function __construct(public string $bindingHash, public string $issuer, public string $subject, public int $version, public int $policyVersion, public string $state, public ?array $profile) {}

    public static function validate(array $data, int $policyVersion, IdentityConfig $config): self
    {
        Contract::require(Contract::keys($data, ['subject', 'version', 'state', 'profile']) && Contract::identifier($data['subject']) && Contract::positive($data['version'])
            && in_array($data['state'], ['active', 'pending', 'suspended', 'revoked', 'deleted'], true), 'invalid_user_snapshot', 502);
        $profile = $data['profile'];
        if (in_array($data['state'], ['revoked', 'deleted'], true)) {
            Contract::require($profile === null, 'invalid_user_snapshot', 502);
        } else {
            Contract::require(is_array($profile) && Contract::keys($profile, ['name', 'email', 'emailVerified', 'picture', 'locale', 'timezone', 'accountType', 'phone', 'organizationName', 'position', 'bio', 'dateOfBirth', 'gender', 'country', 'socialLinks', 'profileCompleted', 'adminNotes', 'tags', 'lastLoginAt'])
                && is_bool($profile['emailVerified']) && in_array($profile['locale'], ['en', 'bg'], true), 'invalid_user_snapshot', 502);
            foreach (['name', 'email'] as $field) {
                Contract::require(is_string($profile[$field]) && mb_check_encoding($profile[$field], 'UTF-8') && mb_strlen($profile[$field]) <= 255 && ! preg_match('/[\\x00-\\x1f\\x7f]/', $profile[$field]), 'invalid_user_snapshot', 502);
            }
            Contract::require(filter_var($profile['email'], FILTER_VALIDATE_EMAIL) !== false, 'invalid_user_snapshot', 502);
            self::validateRichProfile($profile);
            if ($profile['picture'] !== null) {
                $url = $profile['picture'];
                $parts = is_string($url) ? parse_url($url) : false;
                Contract::require(is_string($url) && strlen($url) <= 8192 && filter_var($url, FILTER_VALIDATE_URL) !== false && $parts
                    && ($parts['scheme'] ?? null) === 'https' && ! isset($parts['user']) && ! isset($parts['pass']) && ! preg_match('/[\\x00-\\x20\\x7f]/', $url), 'invalid_user_snapshot', 502);
            }
        }

        return new self($config->bindingHash(), $config->issuer(), $data['subject'], $data['version'], $policyVersion, $data['state'], $profile);
    }

    private static function validateRichProfile(array $profile): void
    {
        Contract::require(SharedProfile::valid($profile) && ($profile['adminNotes'] === null || self::text($profile['adminNotes'], 5000)), 'invalid_user_snapshot', 502);
        $tags = $profile['tags'];
        Contract::require(is_array($tags) && array_is_list($tags) && count($tags) <= 50, 'invalid_user_snapshot', 502);
        foreach ($tags as $tag) {
            Contract::require(self::text($tag, 64) && $tag !== '', 'invalid_user_snapshot', 502);
        }
        Contract::require(count(array_unique($tags)) === count($tags) && ($profile['lastLoginAt'] === null || Contract::date($profile['lastLoginAt']) !== null), 'invalid_user_snapshot', 502);
    }

    private static function text(mixed $value, int $maximum): bool
    {
        return is_string($value) && mb_check_encoding($value, 'UTF-8') && mb_strlen($value) <= $maximum && ! str_contains($value, "\0");
    }

    public function digest(): string
    {
        $profile = $this->profile;
        if ($profile !== null) {
            ksort($profile);
            if (is_array($profile['socialLinks'])) {
                ksort($profile['socialLinks']);
            }
        }

        return hash('sha256', json_encode(['state' => $this->state, 'profile' => $profile], JSON_THROW_ON_ERROR));
    }
}
