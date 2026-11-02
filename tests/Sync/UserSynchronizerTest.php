<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Sync\ProfileSynchronized;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Event;

class UserSynchronizerTest extends TestCase
{
    public function test_jit_projection_is_keyed_by_issuer_and_subject_and_never_links_by_email(): void
    {
        Event::fake([ProfileSynchronized::class]);
        $sync = app(UserSynchronizer::class);
        $first = $sync->sync(['sub' => 'first', 'name' => 'First', 'email' => 'same@example.test', 'email_verified' => true, 'roles' => ['admin']]);
        $second = $sync->sync(['sub' => 'second', 'email' => 'same@example.test']);
        $this->assertNotSame($first->id, $second->id);
        $this->assertSame(2, IdentityUser::query()->count());
        $this->assertSame('https://identity.test/api/auth', $first->issuer);
        $this->assertSame(hash('sha256', "https://identity.test/api/auth\0first"), $first->identity_key);
        $this->assertTrue($first->email_verified);
        $this->assertArrayNotHasKey('roles', $first->getAttributes());
        Event::assertDispatched(ProfileSynchronized::class, fn ($event) => $event->user->is($first) && $event->created);
    }

    public function test_later_verified_userinfo_updates_present_claims_and_preserves_omitted_claims(): void
    {
        $sync = app(UserSynchronizer::class);
        $first = $sync->sync(['sub' => 'person', 'name' => 'Old', 'email' => 'old@example.test', 'picture' => 'https://images.example.test/person.png', 'email_verified' => true]);
        Event::fake([ProfileSynchronized::class]);
        $updated = $sync->sync(['sub' => 'person', 'name' => 'New', 'email_verified' => false]);
        $this->assertSame($first->id, $updated->id);
        $this->assertSame('New', $updated->name);
        $this->assertSame('old@example.test', $updated->email);
        $this->assertFalse($updated->email_verified);
        $this->assertNotNull($updated->synchronized_at);
        Event::assertDispatched(ProfileSynchronized::class, fn ($event) => ! $event->created);
    }

    public function test_changed_email_without_new_verification_claim_clears_previous_verification(): void
    {
        $sync = app(UserSynchronizer::class);
        $sync->sync(['sub' => 'person', 'email' => 'old@example.test', 'email_verified' => true]);
        $changed = $sync->sync(['sub' => 'person', 'email' => 'new@example.test']);
        $this->assertSame('new@example.test', $changed->email);
        $this->assertFalse($changed->email_verified);
    }

    public function test_same_subject_from_another_trusted_issuer_creates_distinct_projection(): void
    {
        $first = app(UserSynchronizer::class)->sync(['sub' => 'person']);
        $this->configure(['identity.consumers.one.origin' => 'https://other-identity.test']);
        $other = app(UserSynchronizer::class)->sync(['sub' => 'person']);
        $this->assertNotSame($first->id, $other->id);
        $this->assertSame(2, IdentityUser::query()->count());
    }

    public function test_profile_hook_fires_only_after_enclosing_consumer_transaction_commits(): void
    {
        $events = [];
        Event::listen(ProfileSynchronized::class, function (ProfileSynchronized $event) use (&$events): void {
            $events[] = $event;
        });
        $connection = (new IdentityUser)->getConnection();
        $connection->beginTransaction();
        app(UserSynchronizer::class)->sync(['sub' => 'rolled-back']);
        $this->assertCount(0, $events);
        $connection->rollBack();
        $this->assertSame(0, IdentityUser::query()->count());
        $this->assertCount(0, $events);
        $connection->beginTransaction();
        app(UserSynchronizer::class)->sync(['sub' => 'committed']);
        $this->assertCount(0, $events);
        $connection->commit();
        $this->assertCount(1, $events);
        $this->assertSame('committed', $events[0]->user->subject);
    }

    public function test_invalid_subject_or_claim_types_cannot_write_projection(): void
    {
        foreach ([[], ['sub' => ''], ['sub' => 'person', 'email_verified' => 'true'], ['sub' => 'person', 'name' => ['malformed']]] as $userinfo) {
            try {
                app(UserSynchronizer::class)->sync($userinfo);
                $this->fail('Invalid verified UserInfo accepted');
            } catch (IdentityException $error) {
                $this->assertSame('userinfo_invalid', $error->errorCode);
            }
        }
        $this->assertSame(0, IdentityUser::query()->count());
    }
}
