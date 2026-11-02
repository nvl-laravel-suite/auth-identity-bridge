<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Users\NativeMappingDefinition;

class UserImportClient
{
    public function __construct(private IdentityConfig $config, private IdentityHttp $http) {}

    /** Imported password hashes stay in this explicit request, never in queued jobs or local profiles. */
    public function import(#[\SensitiveParameter] array $users): UserImportResult
    {
        $sources = $this->preflight($users);

        return UserImportResult::validate($this->http->sync('profiles.import', ['users' => $users]), $this->config, $sources);
    }

    /** Read-only validation shared by the runner and dry run. */
    public function preflight(#[\SensitiveParameter] array $users): array
    {
        Contract::require($this->config->value('sync.enabled', false) === true && $this->config->value('sync.import_enabled', false) === true, 'user_import_disabled', 404);
        app(ExecutionPolicy::class)->assertOutboundAllowed();
        Contract::require(array_is_list($users) && count($users) > 0 && count($users) <= 100, 'user_import_input_invalid', 422);
        $sources = [];
        $emails = [];
        foreach ($users as $user) {
            Contract::require(is_array($user) && Contract::keys($user, ['sourceUserId', 'name', 'email', 'emailVerified'], ['active', 'passwordHash', 'picture', 'locale', 'timezone', 'accountType', 'phone', 'organizationName', 'position', 'bio', 'dateOfBirth', 'gender', 'country', 'socialLinks', 'adminNotes', 'tags', 'roleKeys'])
                && Contract::identifier($user['sourceUserId']) && is_string($user['email']) && strlen($user['email']) <= 254 && filter_var($user['email'], FILTER_VALIDATE_EMAIL) !== false
                && is_string($user['name']) && trim($user['name']) !== '' && mb_strlen($user['name']) <= 120 && is_bool($user['emailVerified'])
                && (! array_key_exists('active', $user) || is_bool($user['active']))
                && (! isset($user['passwordHash']) || (is_string($user['passwordHash']) && strlen($user['passwordHash']) >= 20 && strlen($user['passwordHash']) <= 512))
                && (! array_key_exists('roleKeys', $user) || (Contract::strings($user['roleKeys'], true) && count($user['roleKeys']) <= 50)), 'user_import_input_invalid', 422);
            if (isset($user['passwordHash'])) {
                Contract::require(ImportedPasswordHash::supported($user['passwordHash']), 'user_import_hash_unsupported', 422);
            }
            $email = strtolower($user['email']);
            Contract::require(! in_array($user['sourceUserId'], $sources, true) && ! in_array($email, $emails, true), 'user_import_input_invalid', 422);
            $profile = array_replace(['name' => $user['name'], 'email' => $user['email'], 'emailVerified' => $user['emailVerified'], 'picture' => null, 'locale' => 'en', 'timezone' => 'UTC', 'accountType' => 'individual',
                'phone' => null, 'organizationName' => null, 'position' => null, 'bio' => null, 'dateOfBirth' => null, 'gender' => null, 'country' => null, 'socialLinks' => null, 'profileCompleted' => false, 'adminNotes' => null, 'tags' => [], 'lastLoginAt' => null],
                array_intersect_key($user, array_flip(['name', 'email', 'emailVerified', 'picture', 'locale', 'timezone', 'accountType', 'phone', 'organizationName', 'position', 'bio', 'dateOfBirth', 'gender', 'country', 'socialLinks', 'adminNotes', 'tags'])));
            try {
                UserSnapshot::validate(['subject' => 'input', 'version' => 1, 'state' => 'active', 'profile' => $profile], 1, $this->config);
            } catch (IdentityException) {
                throw new IdentityException('user_import_input_invalid', 422);
            }
            $sources[] = $user['sourceUserId'];
            $emails[] = $email;
        }

        $model = $this->config->value('users.model');
        if ($model !== null) {
            $native = new $model;
            (new NativeMappingDefinition($this->config->value('users'), $native))->preflight($native);
        }

        return $sources;
    }
}
