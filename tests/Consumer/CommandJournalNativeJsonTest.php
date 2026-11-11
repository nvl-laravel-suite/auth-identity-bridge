<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Consumer;

use IdentityPlatform\Laravel\Consumer\CommandJournal;
use IdentityPlatform\Laravel\Consumer\ConsumerCommand;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Tests\Support\NativeJsonOrder;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\DB;

/** A native JSON column (MySQL) returns object keys in its own order, never the written one. */
final class CommandJournalNativeJsonTest extends TestCase
{
    public function test_replayed_command_matches_its_retained_reference_after_native_json_reordering(): void
    {
        $journal = $this->graph()->make(CommandJournal::class);
        $reference = $this->reference();
        $retained = $journal->retain($reference);
        $this->storeAsNativeJson($retained->id);

        $replayed = $journal->retain($reference);

        self::assertFalse($replayed->wasRecentlyCreated);
        self::assertSame($retained->id, $journal->original($reference)->id);
        self::assertSame(1, ConsumerCommand::count());
    }

    public function test_commit_is_recorded_and_repeatable_after_native_json_reordering(): void
    {
        $journal = $this->graph()->make(CommandJournal::class);
        $reference = $this->reference();
        $receipt = ['id' => 'target', 'version' => 3, 'operation' => 'users.profile.update', 'idempotencyKey' => 'command-1', 'changedFields' => ['name']];
        $retained = $journal->retain($reference);
        $this->storeAsNativeJson($retained->id);

        self::assertSame('committed', $journal->committed($reference, $receipt)->state);
        $this->storeAsNativeJson($retained->id);

        self::assertSame('committed', $journal->committed($reference, $receipt)->state);
        self::assertSame('not_required', $journal->refresh($retained->id));
    }

    public function test_a_different_command_under_the_same_key_still_conflicts(): void
    {
        $journal = $this->graph()->make(CommandJournal::class);
        $retained = $journal->retain($this->reference());
        $this->storeAsNativeJson($retained->id);

        $this->expectExceptionObject(new IdentityException('idempotency_conflict', 409));
        $journal->retain([...$this->reference(), 'userId' => 'another-target']);
    }

    /** @return array<string, mixed> */
    private function reference(): array
    {
        $config = $this->graph()->make(IdentityConfig::class);

        return ['contract' => 'platform-consumer-command-reference.v1', 'bindingHash' => $config->bindingHash(), 'issuer' => $config->issuer(), 'applicationId' => $config->applicationId(), 'clientId' => $config->clientId(),
            'localSessionId' => 'ledger-1', 'subject' => 'actor', 'centralSessionId' => 'sid-1', 'organizationId' => null, 'roleId' => 'manager', 'contextVersion' => 2,
            'operation' => 'users.profile.update', 'userId' => 'target', 'expectedVersion' => 2, 'idempotencyKey' => 'command-1', 'changedFields' => ['name']];
    }

    private function storeAsNativeJson(string $id): void
    {
        $row = DB::table('identity_consumer_commands')->where('id', $id)->first();
        self::assertNotNull($row);
        $values = ['reference' => NativeJsonOrder::encode(json_decode($row->reference, true, flags: JSON_THROW_ON_ERROR))];
        if ($row->receipt !== null) {
            $values['receipt'] = NativeJsonOrder::encode(json_decode($row->receipt, true, flags: JSON_THROW_ON_ERROR));
        }
        DB::table('identity_consumer_commands')->where('id', $id)->update($values);
    }
}
