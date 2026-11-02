<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\SharedProfile;

/** Runtime validation of provider JSON only; these values do not themselves grant authority. */
final class ConsumerContract
{
    private const PROFILE = ['id', 'name', 'email', 'locale', 'version', ...SharedProfile::FIELDS];

    private const PERSON = [...self::PROFILE, 'active', 'status', 'grantVersion'];

    private const PURPOSES = ['management', 'delegation', 'password', 'email', 'mfa', 'connections'];

    private const MUTATIONS = [...ManagedContract::WRITES, 'profile.update', 'roles.save', 'access.save', 'invitations.create', 'invitations.revoke', 'invitations.resend', 'step-up.start'];

    /**
     * @param  array<array-key, mixed>  $data
     * @param  array<array-key, mixed>  $input
     */
    public static function validate(string $operation, array $data, array $input, IdentitySession $row, IdentityConfig $config): void
    {
        if (str_starts_with($operation, 'delegation.') && $operation !== 'delegation.options') {
            // Mode, handoff and admission responses have dedicated validators at their use-case boundary.
            return;
        }
        self::result($operation, $data, $input, $row, $config);
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @param  array<array-key, mixed>  $input
     */
    private static function result(string $operation, array $data, array $input, IdentitySession $row, IdentityConfig $config, bool $retained = false): void
    {
        switch ($operation) {
            case 'users.profile.read':
            case 'users.metadata.read':
                ManagedContract::read($operation, $data, $input);

                return;
            case 'users.profile.update':
            case 'users.metadata.update':
                ManagedContract::receipt($operation, $data, $retained ? null : $input);

                return;
            case 'profile.read':
            case 'profile.update':
                self::profile($data);
                self::check($data['id'] === $row->subject);
                if ($operation === 'profile.update' && ! $retained) {
                    self::revision($data['version'], $input);
                }

                return;
            case 'directory.query':
                self::page($data, $input, fn (array $person) => self::person($person));

                return;
            case 'directory.read':
            case 'access.read':
                self::keys($data, [...self::PERSON, 'roles', 'allow', 'deny']);
                self::person($data, false);
                self::check(Contract::identifier($input['userId'] ?? null) && $data['id'] === $input['userId']);
                self::strings($data['roles'], 50);
                self::strings($data['allow'], 250, true);
                self::strings($data['deny'], 250, true);
                self::check(array_intersect($data['allow'], $data['deny']) === []);

                return;
            case 'roles.options.query':
            case 'permissions.options.query':
                self::options($operation, $data, $input);

                return;
            case 'roles.query':
                self::roleCatalog($data);

                return;
            case 'roles.save':
            case 'access.save':
                self::keys($data, ['id', 'version']);
                self::check(Contract::identifier($data['id']) && Contract::positive($data['version']));
                if (! $retained) {
                    self::revision($data['version'], $input);
                    if ($operation === 'access.save') {
                        self::check(Contract::identifier($input['userId'] ?? null) && $data['id'] === $input['userId']);
                    }
                }

                return;
            case 'invitations.query':
                self::page($data, $input, fn (array $invitation) => self::invitation($invitation, $row, $config));

                return;
            case 'invitations.create':
            case 'invitations.revoke':
            case 'invitations.resend':
                self::keys($data, ['id', 'invitation']);
                self::check(Contract::identifier($data['id']) && is_array($data['invitation']));
                self::invitation($data['invitation'], $row, $config, $retained);
                self::check($data['id'] === $data['invitation']['id']);
                if ($operation === 'invitations.revoke') {
                    self::check($data['invitation']['status'] === 'revoked');
                } else {
                    self::check($data['invitation']['status'] === 'pending');
                }
                if (! $retained) {
                    if ($operation === 'invitations.create') {
                        self::check(is_string($input['email'] ?? null) && $data['invitation']['email'] === strtolower($input['email']) && $data['invitation']['version'] === 1);
                        self::strings($input['roles'] ?? null, 50);
                        $ids = array_column($data['invitation']['roles'], 'id');
                        self::check(count($ids) === count($input['roles']) && array_diff($ids, $input['roles']) === []);
                    } else {
                        self::check(Contract::identifier($input['invitationId'] ?? null) && $data['id'] === $input['invitationId']);
                        self::revision($data['invitation']['version'], $input);
                    }
                }

                return;
            case 'operations.status':
                self::keys($data, ['operation', 'status', 'data']);
                self::check(is_string($data['operation']) && in_array($data['operation'], self::MUTATIONS, true) && in_array($data['status'], ['pending', 'completed'], true));
                if ($data['status'] === 'pending') {
                    self::check($data['data'] === null);
                } else {
                    self::check(is_array($data['data']));
                    // Status requests contain only an idempotency key, not the original target or revision.
                    self::result($data['operation'], $data['data'], [], $row, $config, true);
                    if (in_array($data['operation'], ManagedContract::WRITES, true)) {
                        self::check($data['data']['idempotencyKey'] === ($input['idempotencyKey'] ?? null));
                    }
                }

                return;
            case 'step-up.start':
                self::keys($data, ['id', 'authorizationUrl', 'expiresAt', 'purpose']);
                self::check(Contract::identifier($data['id']) && self::purpose($data['purpose']) && ($retained || $data['purpose'] === ($input['purpose'] ?? null)));
                self::check($data['authorizationUrl'] === $config->origin().'/consumer/step-up?id='.rawurlencode($data['id']));
                self::future($data['expiresAt'], 300, $retained);

                return;
            case 'step-up.redeem':
                self::keys($data, ['purpose', 'centralSessionId', 'verifiedAt', 'expiresAt']);
                self::check(self::purpose($data['purpose']) && $data['purpose'] === ($input['purpose'] ?? null) && $data['centralSessionId'] === $row->sid);
                $verified = Contract::date($data['verifiedAt']);
                $expires = Contract::date($data['expiresAt']);
                $now = microtime(true);
                self::check($verified !== null && $expires !== null && $verified <= $now && $verified > $now - 300 && $expires > $now && abs($expires - $verified - 300) < 0.001);

                return;
            case 'delegation.options':
                self::keys($data, ['policyVersion', 'authorityVersion', 'operations', 'expiresAt', 'organizationId']);
                self::check(Contract::positive($data['policyVersion']) && Contract::positive($data['authorityVersion']) && $data['organizationId'] === ($row->selection['organizationId'] ?? null));
                self::future($data['expiresAt'], 30 * 86400);
                self::list($data['operations'], 100);
                self::check($data['operations'] !== []);
                foreach ($data['operations'] as $operation) {
                    self::check(is_array($operation));
                    self::keys($operation, ['key', 'permissions', 'write']);
                    self::check(self::permission($operation['key']) && is_bool($operation['write']));
                    self::strings($operation['permissions'], 250, true);
                    self::check($operation['permissions'] !== []);
                }
                self::unique($data['operations'], 'key');

                return;
            default:
                throw new IdentityException('invalid_consumer_response', 502);
        }
    }

    /**
     * @param  array<array-key, mixed>  $data
     *
     * @phpstan-assert array{id: non-empty-string, name: string, email: non-empty-string, locale: 'en'|'bg', version: positive-int, ...} $data
     */
    private static function profile(array $data, bool $exact = true): void
    {
        if ($exact) {
            self::keys($data, self::PROFILE);
        }
        self::check(Contract::identifier($data['id'] ?? null) && self::text($data['name'] ?? null) && self::email($data['email'] ?? null)
            && in_array($data['locale'] ?? null, ['en', 'bg'], true) && Contract::positive($data['version'] ?? null) && SharedProfile::valid($data));
    }

    /** @param array<array-key, mixed> $data */
    private static function person(array $data, bool $exact = true): void
    {
        if ($exact) {
            self::keys($data, self::PERSON);
        }
        self::profile($data, false);
        self::check(is_bool($data['active'] ?? null) && in_array($data['status'] ?? null, ['active', 'revoked', 'pending_provisioning'], true) && Contract::positive($data['grantVersion'] ?? null));
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @param  array<array-key, mixed>  $input
     */
    private static function page(array $data, array $input, callable $validate): void
    {
        self::keys($data, ['items', 'nextCursor']);
        $limit = $input['limit'] ?? 25;
        self::check((is_int($limit) || (is_string($limit) && ctype_digit($limit))) && (int) $limit >= 1 && (int) $limit <= 100);
        self::list($data['items'], (int) $limit);
        foreach ($data['items'] as $item) {
            self::check(is_array($item));
            $validate($item);
        }
        self::unique($data['items'], 'id');
        $last = $data['items'][array_key_last($data['items'])] ?? null;
        self::check(Contract::nullableIdentifier($data['nextCursor']) && ($data['nextCursor'] === null || (count($data['items']) === (int) $limit && is_array($last) && $data['nextCursor'] === ($last['id'] ?? null))));
    }

    /** @param array<array-key, mixed> $data */
    private static function roleCatalog(array $data): void
    {
        self::keys($data, ['version', 'roles', 'permissions']);
        self::check(Contract::positive($data['version']));
        self::list($data['permissions'], 250);
        foreach ($data['permissions'] as $permission) {
            self::check(is_array($permission));
            self::keys($permission, ['key', 'description']);
            self::check(self::permission($permission['key']) && self::text($permission['description']));
        }
        self::unique($data['permissions'], 'key');
        self::list($data['roles'], 1000);
        foreach ($data['roles'] as $role) {
            self::check(is_array($role));
            self::keys($role, ['id', 'key', 'name', 'protected', 'permissions']);
            self::check(Contract::identifier($role['id']) && self::permission($role['key']) && self::text($role['name']) && is_bool($role['protected']));
            self::strings($role['permissions'], 250, true);
            self::check(array_diff($role['permissions'], array_column($data['permissions'], 'key')) === []);
        }
        self::unique($data['roles'], 'id');
        self::unique($data['roles'], 'key');
    }

    /**
     * @param  array<array-key, mixed>  $data
     *
     * @phpstan-assert array{id: non-empty-string, email: non-empty-string, version: positive-int, status: 'pending'|'accepted'|'revoked'|'expired', roles: list<array{id: non-empty-string, name: string}>, ...} $data
     */
    private static function invitation(array $data, IdentitySession $row, IdentityConfig $config, bool $historical = false): void
    {
        self::keys($data, ['id', 'email', 'applicationId', 'applicationName', 'organizationId', 'organizationName', 'membershipRole', 'roles', 'metadata', 'version', 'status', 'createdAt', 'expiresAt']);
        self::check(Contract::identifier($data['id']) && self::email($data['email']) && $data['applicationId'] === $config->applicationId() && $data['organizationId'] === ($row->selection['organizationId'] ?? null)
            && ($data['applicationName'] === null || self::text($data['applicationName'])) && ($data['organizationName'] === null || self::text($data['organizationName']))
            && ($data['organizationId'] === null ? $data['membershipRole'] === null : in_array($data['membershipRole'], ['owner', 'admin', 'member'], true))
            && Contract::positive($data['version']) && in_array($data['status'], ['pending', 'accepted', 'revoked', 'expired'], true));
        $created = Contract::date($data['createdAt']);
        $expires = Contract::date($data['expiresAt']);
        $now = microtime(true);
        self::check($created !== null && $expires !== null && $created <= $now && $expires > $created
            && ($historical || $data['status'] !== 'pending' || $expires > $now) && ($data['status'] !== 'expired' || $expires <= $now));
        self::list($data['roles'], 50);
        foreach ($data['roles'] as $role) {
            self::check(is_array($role));
            self::keys($role, ['id', 'name']);
            self::check(Contract::identifier($role['id']) && self::text($role['name']));
        }
        self::unique($data['roles'], 'id');
        self::check(is_array($data['metadata']) && count($data['metadata']) <= 20);
        foreach ($data['metadata'] as $key => $value) {
            self::check(is_string($key) && preg_match('/^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$/D', $key) === 1
                && ($value === null || is_bool($value) || is_int($value) || (is_float($value) && is_finite($value)) || (is_string($value) && self::text($value, 500))));
        }
        $encoded = json_encode($data['metadata']);
        self::check(is_string($encoded) && strlen($encoded) <= 4096);
    }

    private static function purpose(mixed $value): bool
    {
        return is_string($value) && in_array($value, self::PURPOSES, true);
    }

    /** @param array<array-key, mixed> $input */
    private static function revision(int $version, array $input): void
    {
        self::check(is_int($input['expectedVersion'] ?? null) && $input['expectedVersion'] >= 0 && $version === $input['expectedVersion'] + 1);
    }

    private static function future(mixed $value, int $maximum, bool $historical = false): void
    {
        $deadline = Contract::date($value);
        $now = microtime(true);
        self::check($deadline !== null && ($historical || $deadline > $now) && $deadline <= $now + $maximum);
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @param  array<array-key, mixed>  $input
     */
    private static function options(string $operation, array $data, array $input): void
    {
        $permissions = $operation === 'permissions.options.query';
        self::keys($data, ['items', 'nextCursor', 'selected']);
        self::list($data['items'], 25);
        self::strings($input['selectedValues'] ?? [], $permissions ? 250 : 50, $permissions);
        self::list($data['selected'], $permissions ? 250 : 50);
        self::check($data['nextCursor'] === null || (is_string($data['nextCursor']) && strlen($data['nextCursor']) <= 2048 && preg_match('/^[A-Za-z0-9_-]+$/D', $data['nextCursor']) === 1));
        foreach ($data['items'] as $item) {
            self::check(is_array($item));
            self::keys($item, ['value', 'label', 'hint']);
            self::check($permissions ? self::permission($item['value']) : Contract::identifier($item['value']));
            self::check(self::text($item['label'], $permissions ? 128 : 120) && self::text($item['hint'], $permissions ? 120 : 128));
            self::check(! $permissions || $item['label'] === $item['value']);
        }
        self::unique($data['items'], 'value');
        foreach ($data['selected'] as $item) {
            self::check(is_array($item));
            self::check(in_array($item['state'] ?? null, ['editable', 'unavailable'], true));
            self::keys($item, $item['state'] === 'editable' ? ['value', 'state', 'label', 'hint'] : ['value', 'state']);
            self::check($permissions ? self::permission($item['value']) : Contract::identifier($item['value']));
            if ($item['state'] === 'editable') {
                self::check(self::text($item['label'], $permissions ? 128 : 120) && self::text($item['hint'], $permissions ? 120 : 128));
                self::check(! $permissions || ($item['label'] === $item['value'] && $item['hint'] === ''));
            }
        }
        self::unique($data['selected'], 'value');
        $requested = $input['selectedValues'] ?? [];
        $resolved = array_column($data['selected'], 'value');
        sort($requested);
        sort($resolved);
        self::check($requested === $resolved);
    }

    /** @phpstan-assert list<non-empty-string> $value */
    private static function strings(mixed $value, int $maximum, bool $permissions = false): void
    {
        self::check(Contract::strings($value, $permissions) && count($value) <= $maximum);
    }

    /** @phpstan-assert list<mixed> $value */
    private static function list(mixed $value, int $maximum): void
    {
        self::check(is_array($value) && array_is_list($value) && count($value) <= $maximum);
    }

    /** @param array<array-key, mixed> $items */
    private static function unique(array $items, string $column): void
    {
        $values = array_column($items, $column);
        self::check(Contract::strings($values));
    }

    /** @phpstan-assert-if-true =non-empty-string $value */
    private static function permission(mixed $value): bool
    {
        return is_string($value) && preg_match('/^[a-z][a-z0-9._:-]{1,127}$/D', $value) === 1;
    }

    /** @phpstan-assert-if-true =non-empty-string $value */
    private static function email(mixed $value): bool
    {
        return is_string($value) && strlen($value) <= 254 && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }

    /** @phpstan-assert-if-true =string $value */
    private static function text(mixed $value, int $maximum = 4096): bool
    {
        return is_string($value) && mb_check_encoding($value, 'UTF-8') && mb_strlen($value) <= $maximum && ! str_contains($value, "\0");
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @param  list<array-key>  $keys
     */
    private static function keys(array $data, array $keys): void
    {
        self::check(Contract::keys($data, $keys));
    }

    /** @phpstan-assert true $condition */
    private static function check(bool $condition): void
    {
        Contract::require($condition, 'invalid_consumer_response', 502);
    }
}
