<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Authorization\Contract;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/** One schema for direct and transformed fields; omitted sources never become null. */
final readonly class NativeMappingDefinition
{
    public const SOURCES = ['name', 'email', 'picture', 'state', 'emailVerified', 'email_verified_at', 'locale', 'timezone', 'accountType', 'phone', 'organizationName', 'position', 'bio', 'dateOfBirth', 'gender', 'country', 'socialLinks', 'profileCompleted', 'adminNotes', 'tags', 'lastLoginAt'];

    /** @var array<string, array{column: string, transform: class-string<NativeValueTransform>|null, cast: string|null, options: array<array-key, mixed>}> */
    public array $fields;

    /** @param array{fields: array<array-key, mixed>, protected_fields?: list<string>, local_fields?: list<string>, readonly_fields?: list<string>, native_group?: array{name: string, writer: string, epoch: int}|null} $users */
    public function __construct(array $users, ?Model $model)
    {
        $fields = [];
        $destinations = [];
        $protected = array_merge(['id', 'password', 'password_hash', 'remember_token', 'roles', 'permissions', 'is_admin', 'security', 'owner_id', 'user_id', 'created_at', 'updated_at', 'deleted_at'], $users['protected_fields'] ?? [], $users['local_fields'] ?? [], $users['readonly_fields'] ?? []);
        if ($model) {
            $protected[] = $model->getKeyName();
            Contract::require($model instanceof Authenticatable, 'identity_user_mapping_invalid', 503);
            $protected[] = $model->getAuthIdentifierName();
            $protected[] = $model->getAuthPasswordName();
            $protected[] = $model->getRememberTokenName();
        }
        foreach ($users['fields'] as $source => $input) {
            Contract::require(in_array($source, self::SOURCES, true), 'identity_user_mapping_invalid', 503);
            $entry = is_string($input) ? ['column' => $input] : $input;
            Contract::require(is_array($entry) && isset($entry['column']) && array_diff(array_keys($entry), ['column', 'transform', 'cast', 'options']) === [], 'identity_user_mapping_invalid', 503);
            $entry += ['transform' => null, 'cast' => null, 'options' => []];
            $column = $entry['column'];
            Contract::require(is_string($column) && preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D', $column) === 1 && ! in_array($column, $protected, true) && ! preg_match('/(?:_id|_uuid|_key|_token|_secret|_password|_roles|_permissions)$/i', $column) && ! in_array($column, $destinations, true), 'identity_user_mapping_invalid', 503);
            self::destination($source, $column, $users);
            Contract::require(is_array($entry['options']), 'identity_user_mapping_invalid', 503);
            if ($entry['transform'] !== null) {
                Contract::require(is_string($entry['transform']) && is_subclass_of($entry['transform'], NativeValueTransform::class) && (new \ReflectionClass($entry['transform']))->isInstantiable(), 'identity_user_mapping_invalid', 503);
                $constructor = (new \ReflectionClass($entry['transform']))->getConstructor();
                Contract::require($constructor === null || $constructor->getNumberOfRequiredParameters() === 0, 'identity_user_mapping_invalid', 503);
                $entry['transform']::validate($entry['options']);
            } else {
                Contract::require($entry['options'] === [], 'identity_user_mapping_invalid', 503);
            }
            Contract::require($entry['cast'] === null || in_array($entry['cast'], ['string', 'boolean', 'integer', 'float', 'array', 'json', 'date', 'datetime', 'immutable_date', 'immutable_datetime'], true) || (is_string($entry['cast']) && enum_exists($entry['cast']) && is_subclass_of($entry['cast'], \BackedEnum::class)), 'identity_user_mapping_invalid', 503);
            if ($model !== null) {
                Contract::require(! ($model->hasGetMutator($column) && ! $model->hasSetMutator($column)) && ! ($model->hasAttributeGetMutator($column) && ! $model->hasAttributeSetMutator($column)), 'identity_user_mapping_invalid', 503);
            }
            $fields[$source] = ['column' => $column, 'transform' => $entry['transform'], 'cast' => $entry['cast'], 'options' => $entry['options']];
            $destinations[] = $column;
        }
        Contract::require(! isset($fields['email_verified_at']) || isset($fields['email']), 'identity_user_mapping_invalid', 503);
        Contract::require($model !== null || $fields === [], 'identity_user_mapping_invalid', 503);
        $this->fields = $fields;
    }

    /** Mandatory authority rules are additive to host ownership declarations, never overridable.
     *
     * @param  array{native_group?: array{name: string, writer: string, epoch: int}|null, ...}  $users
     */
    private static function destination(string $source, string $column, array $users): void
    {
        // Normalize conventional snake_case, camelCase and acronym spellings only for classification.
        $name = preg_replace('/([A-Z]+)([A-Z][a-z])/', '$1_$2', $column);
        Contract::require(is_string($name), 'identity_user_mapping_invalid', 503);
        $name = preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', $name);
        Contract::require(is_string($name), 'identity_user_mapping_invalid', 503);
        $name = strtolower($name);
        $authority = '/(?:^|_)(?:roles?|permissions?|privileges?|privileged|admin|administrator|superadmin|superuser|sudo|mfa|otp|totp|two_factor|twofactor|security|credentials?|passwords?|passkeys?|auth|authentication|authorization)(?:_|$)/';
        // The contract's operator-note field is governance data, not an administrator privilege.
        $governanceNotes = $source === 'adminNotes' && $name === 'admin_notes' && ($users['native_group'] ?? null) === null;
        Contract::require(($governanceNotes || ! preg_match($authority, $name)) && ! in_array($name, ['is_staff', 'is_root', 'is_moderator', 'access_level', 'access_rights', 'abilities', 'scopes', 'claims', 'recovery_codes', 'backup_codes'], true), 'identity_user_mapping_invalid', 503);
        $lifecycle = preg_match('/^(?:(?:is|account|user|identity|login)_)?(?:active|enabled|disabled|locked)(?:_flag)?$/', $name) || in_array($name, ['can_login', 'account_status', 'user_status', 'identity_status'], true);
        if ($lifecycle) {
            Contract::require($source === 'state' && ($users['native_group'] ?? null) === null, 'identity_user_mapping_invalid', 503);
        }
    }

    /**
     * @param  array<array-key, mixed>  $facts
     * @return array<string, mixed>
     */
    public function values(array $facts, Model $model): array
    {
        $values = [];
        $casts = [];
        $this->preflight($model);
        foreach ($this->fields as $source => $field) {
            if (! array_key_exists($source, $facts)) {
                continue;
            }
            $value = $facts[$source];
            if ($field['transform'] !== null) {
                $value = (new $field['transform'])->transform($value, $field['options']);
            }
            if ($field['cast'] !== null) {
                $casts[$field['column']] = $field['cast'];
            }
            $values[$field['column']] = $value;
        }
        $model->mergeCasts($casts);

        return $values;
    }

    /** Read-only host schema validation for import/worker startup; never changes native tables. */
    public function preflight(Model $model): void
    {
        $schema = $model->getConnection()->getSchemaBuilder();
        $columns = array_column($schema->getColumns($model->getTable()), null, 'name');
        $foreign = [];
        foreach ($schema->getForeignKeys($model->getTable()) as $key) {
            $foreign = array_merge($foreign, $key['columns']);
        }
        foreach ($this->fields as $field) {
            $column = $field['column'];
            Contract::require(isset($columns[$column]) && ($columns[$column]['generation'] ?? null) === null && ! in_array($column, $foreign, true), 'identity_user_mapping_invalid', 503);
        }
    }
}
