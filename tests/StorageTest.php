<?php

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;

class StorageTest extends TestCase
{
    public function test_session_lookup_is_bound_to_consumer_and_tokens_do_not_serialize(): void
    {
        IdentitySession::create(['id' => 'session-a', 'binding_hash' => 'foreign', 'user_id' => null, 'subject' => 'subject-a', 'sid' => 'sid-a', 'token_vault' => 'private', 'selection' => [], 'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->assertNull(app(SessionRepository::class)->find('session-a'));
        $this->assertArrayNotHasKey('token_vault', IdentitySession::first()->toArray());
    }
}
