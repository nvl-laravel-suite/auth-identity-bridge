<?php

namespace IdentityPlatform\Laravel\Tests\Consumer;

use IdentityPlatform\Laravel\Consumer\ManagedContract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ManagedContractTest extends TestCase
{
    public function test_normalizes_changes_without_inventing_omitted_fields(): void
    {
        $input = ManagedContract::input('users.profile.update', self::input(['name' => '  Name  ', 'phone' => null, 'socialLinks' => ['site' => 'https://EXAMPLE.test:443']]));
        self::assertSame(['name' => 'Name', 'phone' => null, 'socialLinks' => ['site' => 'https://example.test/']], $input['changes']);
        self::assertSame('Correct shared facts', $input['reason']);
        self::assertSame(['id' => 'target', 'version' => 2, 'writableFields' => [], 'fields' => ['phone' => null]], ManagedContract::read('users.profile.read', ['id' => 'target', 'version' => 2, 'writableFields' => [], 'fields' => ['phone' => null]], ['userId' => 'target']));
        self::assertSame([], ManagedContract::read('users.metadata.read', ['id' => 'target', 'version' => 2, 'writableFields' => [], 'fields' => []], ['userId' => 'target'])['fields']);
    }

    public function test_metadata_normalizes_tags_and_preserves_empty_text(): void
    {
        $result = ManagedContract::input('users.metadata.update', self::input(['adminNotes' => '  ', 'tags' => [' z ', 'a']]));
        self::assertSame(['adminNotes' => '', 'tags' => ['a', 'z']], $result['changes']);
    }

    #[DataProvider('invalidInputs')]
    public function test_rejects_invalid_input_before_transport(string $operation, array $input): void
    {
        $this->expectException(IdentityException::class);
        ManagedContract::input($operation, $input);
    }

    public static function invalidInputs(): array
    {
        $cases = [];
        foreach ([[], ['profileCompleted' => true], ['email' => 'x@example.test'], ['name' => null], ['name' => ''], ['timezone' => 'US/Eastern'], ['timezone' => 'Etc/UTC'], ['dateOfBirth' => '2001-02-29'], ['country' => 'bg'], ['socialLinks' => ['site' => 'https://user:pass@example.test']], ['bio' => "nul\0"], ['name' => str_repeat('😀', 61)]] as $i => $changes) {
            $cases['profile-'.$i] = ['users.profile.update', self::input($changes)];
        }
        foreach ([['tags' => null], ['tags' => ['a', ' a ']], ['lastLoginAt' => '2026-01-01'], ['adminNotes' => str_repeat('😀', 2501)], ['phone' => null]] as $i => $changes) {
            $cases['metadata-'.$i] = ['users.metadata.update', self::input($changes)];
        }
        $cases['extra read'] = ['users.profile.read', ['userId' => 'target', 'actor' => 'forged']];
        $cases['missing read'] = ['users.metadata.read', []];
        $cases['null key'] = ['users.profile.update', array_replace(self::input(['name' => 'Name']), ['idempotencyKey' => null])];
        $cases['unsafe next version'] = ['users.profile.update', array_replace(self::input(['name' => 'Name']), ['expectedVersion' => 9007199254740991])];

        return $cases;
    }

    public function test_utf16_length_boundary_and_calendar_year_zero_match_node(): void
    {
        self::assertSame(str_repeat('😀', 60), ManagedContract::input('users.profile.update', self::input(['name' => str_repeat('😀', 60)]))['changes']['name']);
        self::assertSame('0000-02-29', ManagedContract::input('users.profile.update', self::input(['dateOfBirth' => '0000-02-29']))['changes']['dateOfBirth']);
    }

    #[DataProvider('invalidReceipts')]
    public function test_binds_receipt_to_original_command(array $patch): void
    {
        $input = self::input(['name' => 'Name', 'phone' => null]);
        $receipt = ['id' => 'target', 'version' => 3, 'operation' => 'users.profile.update', 'idempotencyKey' => 'command-1', 'changedFields' => ['name', 'phone']];
        $this->expectException(IdentityException::class);
        ManagedContract::receipt('users.profile.update', array_replace($receipt, $patch), $input);
    }

    public static function invalidReceipts(): array
    {
        return array_map(fn ($patch) => [$patch], [['id' => 'actor'], ['version' => 4], ['operation' => 'users.metadata.update'], ['idempotencyKey' => 'other'], ['changedFields' => ['phone', 'name']], ['changedFields' => ['name']], ['changedFields' => ['name', 'name']], ['reason' => 'private'], ['fields' => ['name' => 'private']]]);
    }

    #[DataProvider('invalidReads')]
    public function test_strict_partial_read_result(string $operation, array $fields): void
    {
        $this->expectException(IdentityException::class);
        ManagedContract::read($operation, ['id' => 'target', 'version' => 2, 'writableFields' => [], 'fields' => $fields], ['userId' => 'target']);
    }

    public static function invalidReads(): array
    {
        return [['users.profile.read', ['adminNotes' => 'private']], ['users.profile.read', ['password' => 'private']], ['users.metadata.read', ['lastLoginIp' => 'private']], ['users.metadata.read', ['profileCompleted' => true]], ['users.profile.read', ['name' => null]]];
    }

    #[DataProvider('validHints')]
    public function test_read_hints_are_explicit_sorted_subsets(string $operation, array $fields, array $writableFields): void
    {
        $data = ['id' => 'target', 'version' => 2, 'fields' => $fields, 'writableFields' => $writableFields];
        self::assertSame($data, ManagedContract::read($operation, $data, ['userId' => 'target']));
    }

    public static function validHints(): array
    {
        $profile = ['name' => 'Person', 'phone' => null, 'accountType' => 'company', 'profileCompleted' => true];
        $metadata = ['adminNotes' => null, 'tags' => []];

        return [
            ['users.profile.read', $profile, []], ['users.profile.read', $profile, ['name']], ['users.profile.read', $profile, ['accountType', 'name', 'phone']],
            ['users.metadata.read', $metadata, []], ['users.metadata.read', $metadata, ['tags']], ['users.metadata.read', $metadata, ['adminNotes', 'tags']],
        ];
    }

    #[DataProvider('invalidHints')]
    public function test_read_rejects_malformed_hints_and_bindings(string $operation, array $patch): void
    {
        $data = ['id' => 'target', 'version' => 2, 'fields' => $operation === 'users.profile.read' ? ['name' => 'Person', 'phone' => null, 'profileCompleted' => true] : ['tags' => []], 'writableFields' => []];
        $this->expectException(IdentityException::class);
        ManagedContract::read($operation, array_replace($data, $patch), ['userId' => 'target']);
    }

    public static function invalidHints(): array
    {
        $cases = [];
        foreach ([null, 'name', new \stdClass, [1 => 'name'], ['name', 'name'], ['phone', 'name'], ['bio'], ['adminNotes'], ['unknown'], ['profileCompleted'], [1]] as $hint) {
            $cases[] = ['users.profile.read', ['writableFields' => $hint]];
        }
        foreach ([null, 'tags', new \stdClass, [1 => 'tags'], ['tags', 'tags'], ['tags', 'adminNotes'], ['adminNotes'], ['name'], ['unknown'], ['profileCompleted'], [1]] as $hint) {
            $cases[] = ['users.metadata.read', ['writableFields' => $hint]];
        }
        foreach (['users.profile.read', 'users.metadata.read'] as $operation) {
            foreach ([['id' => 'other'], ['version' => 0], ['actor' => 'forged']] as $patch) {
                $cases[] = [$operation, $patch];
            }
        }

        return $cases;
    }

    public function test_old_missing_hint_response_is_rejected(): void
    {
        $this->expectException(IdentityException::class);
        ManagedContract::read('users.profile.read', ['id' => 'target', 'version' => 2, 'fields' => ['name' => 'Person']], ['userId' => 'target']);
    }

    public static function input(array $changes): array
    {
        return ['userId' => 'target', 'expectedVersion' => 2, 'changes' => $changes, 'reason' => '  Correct shared facts  ', 'idempotencyKey' => 'command-1'];
    }
}
