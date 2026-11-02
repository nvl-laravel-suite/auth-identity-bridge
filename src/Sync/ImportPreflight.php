<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Models\IdentityProjectionOwner;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Users\NativeMappingDefinition;
use IdentityPlatform\Laravel\Users\NativeOwner;
use IdentityPlatform\Laravel\Users\ProjectionOwnership;
use IdentityPlatform\Laravel\Users\RetainedNativeLifecycle;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\SoftDeletingScope;

final class ImportPreflight
{
    public function __construct(private IdentityConfig $config, private UserImportClient $client, private ConsumerRegistry $registry) {}

    public function assertPausedProvisioning(): void
    {
        $policy = $this->config->value('users.lifecycle_policy', RetainedNativeLifecycle::class);
        Contract::require($policy !== null, 'identity_user_mapping_invalid', 503);
        Contract::require($this->config->value('sync.provision_missing', false) === false && (new $policy)->mayProvision('active') === false, 'user_import_provisioning_enabled', 409);
    }

    /** Returns nonsecret immutable references only. Does not claim remote eligibility or collision validation.
     *
     * @return list<array{id: string, binding_hash: string, source_name: string, source_user_id: string, native_user_id: string, native_type: class-string<Model>, physical_key: string}>
     */
    public function page(#[\SensitiveParameter] UserImportPage $page, string $source, ?string $cursor, int $limit): array
    {
        $entries = $page->entries();
        Contract::require(array_is_list($entries) && count($entries) <= $limit && ($page->nextCursor === null || (preg_match('/^[A-Za-z0-9_.:\/-]{1,1024}$/D', $page->nextCursor) === 1 && $page->nextCursor !== $cursor && $entries !== [])), 'user_import_cursor_invalid', 422);
        $entries = array_map(function (mixed $entry): UserImportEntry {
            Contract::require($entry instanceof UserImportEntry, 'user_import_input_invalid', 422);

            return $entry;
        }, $entries);
        if ($entries === []) {
            return [];
        }
        $sourceIds = array_map(fn ($entry) => $entry->payload()['sourceUserId'] ?? null, $entries);
        Contract::require(count(array_unique($sourceIds, SORT_REGULAR)) === count($sourceIds), 'user_import_duplicate_source', 422);
        $inputs = array_map(fn ($entry) => $entry->payload(), $entries);
        $this->client->preflight($inputs);
        $class = $this->config->value('users.model');
        Contract::require($class !== null, 'user_import_association_invalid', 422);
        $definition = new NativeMappingDefinition($this->config->value('users'), new $class);
        $definition->preflight(new $class);
        $references = [];
        $physicalKeys = [];
        foreach ($entries as $index => $entry) {
            $input = $inputs[$index];
            $nativeId = (string) $entry->nativeUserId;
            Contract::require(preg_match('/^[A-Za-z0-9_.:-]{1,255}$/D', $nativeId) === 1, 'user_import_association_invalid', 422);
            $native = $class::query()->whereKey($nativeId)->first();
            if ($native === null && in_array(SoftDeletes::class, class_uses_recursive($class), true)) {
                Contract::require(! $class::query()->withoutGlobalScope(SoftDeletingScope::class)->whereKey($nativeId)->exists(), 'user_import_native_soft_deleted', 409);
            }
            Contract::require($native instanceof Authenticatable && (is_string($native->getKey()) || is_int($native->getKey())) && (string) $native->getKey() === $nativeId, 'user_import_native_missing', 409);
            Contract::require($native->getConnection()->getName() === (new ImportRun)->getConnection()->getName(), 'identity_user_connection_mismatch', 503);
            $id = hash('sha256', $this->config->bindingHash()."\0".$input['sourceUserId']);
            $reference = ['id' => $id, 'binding_hash' => $this->config->bindingHash(), 'source_name' => $source, 'source_user_id' => $input['sourceUserId'], 'native_user_id' => $nativeId, 'native_type' => $class, 'physical_key' => ProjectionOwnership::physical($native)];
            Contract::require(! in_array($reference['physical_key'], $physicalKeys, true), 'user_import_owner_conflict', 409);
            $physicalKeys[] = $reference['physical_key'];
            $existing = ImportBinding::find($id);
            if ($existing) {
                foreach ($reference as $key => $value) {
                    Contract::require($existing->{$key} === $value, 'user_import_binding_changed', 409);
                }
            }
            $reserved = ImportBinding::query()->where('binding_hash', $this->config->bindingHash())->where('physical_key', $reference['physical_key'])->first();
            Contract::require(! $reserved || $reserved->id === $id, 'user_import_owner_conflict', 409);
            $import = UserImportLink::find($id);
            Contract::require(! $import || $import->owner_key === NativeOwner::key($native), 'user_import_owner_conflict', 409);
            foreach (IdentityUserLink::query()->where('user_id', $nativeId)->get() as $link) {
                if (! is_subclass_of($link->user_type, Model::class)) {
                    continue;
                }
                $other = new $link->user_type;
                if ($other->getTable() === $native->getTable() && $other->getConnection()->getName() === $native->getConnection()->getName()) {
                    Contract::require($import && $link->binding_hash === $this->config->bindingHash() && $link->projection_id === $import->projection_id, 'user_import_owner_conflict', 409);
                }
            }
            $owner = IdentityProjectionOwner::find(hash('sha256', 'native'."\0".$reference['physical_key']));
            if ($owner) {
                $group = $this->config->value('users.native_group');
                $writer = $group ? $this->registry->get($group['writer'])->bindingHash() : $this->config->bindingHash();
                Contract::require($owner->writer_binding === $writer && $owner->epoch === ($group['epoch'] ?? 1) && $owner->group_name === ($group['name'] ?? null), 'identity_projection_owner_fenced', 409);
                Contract::require($import !== null && $owner->identity_key === hash('sha256', $import->issuer."\0".$import->subject), 'user_import_owner_conflict', 409);
            }
            // Apply registered transforms/casts only to this unsaved model and inspect required mapped values.
            $facts = $input + ['picture' => null, 'adminNotes' => null, 'tags' => []];
            $facts['state'] = ($input['active'] ?? true) ? 'active' : 'suspended';
            $facts['email_verified_at'] = $input['emailVerified'] ? now() : null;
            $values = $definition->values($facts, $native);
            $native->forceFill($values);
            $columns = array_column($native->getConnection()->getSchemaBuilder()->getColumns($native->getTable()), null, 'name');
            foreach ($values as $column => $value) {
                Contract::require($columns[$column]['nullable'] || ($native->getAttributes()[$column] ?? null) !== null, 'user_import_native_required', 422);
            }
            $references[] = $reference;
        }

        return $references;
    }
}
