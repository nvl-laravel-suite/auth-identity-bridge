<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSnapshot;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class RichNativeUser extends User
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['social_links' => 'array', 'tags' => 'array', 'profile_completed' => 'boolean'];
    }
}

class RichUserSnapshotTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('rich_native_users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email');
            foreach (['locale', 'timezone', 'account_type', 'phone', 'organization_name', 'position', 'bio', 'date_of_birth', 'gender', 'country', 'admin_notes', 'last_login_at'] as $field) {
                $table->text($field)->nullable();
            }
            $table->json('social_links')->nullable();
            $table->json('tags')->nullable();
            $table->boolean('profile_completed')->default(false);
            $table->string('local_role')->default('host-admin');
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.provision_missing' => true, 'identity.consumers.one.users.model' => RichNativeUser::class,
            'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email', 'locale' => 'locale', 'timezone' => 'timezone', 'accountType' => 'account_type', 'phone' => 'phone',
                'organizationName' => 'organization_name', 'position' => 'position', 'bio' => 'bio', 'dateOfBirth' => 'date_of_birth', 'gender' => 'gender', 'country' => 'country',
                'socialLinks' => 'social_links', 'profileCompleted' => 'profile_completed', 'adminNotes' => 'admin_notes', 'tags' => 'tags', 'lastLoginAt' => 'last_login_at']]);
    }

    private function snapshot(array $changes = [], int $version = 1): UserSnapshot
    {
        return UserSnapshot::validate(['subject' => 'person', 'version' => $version, 'state' => 'active', 'profile' => ProfileFixture::profile($changes)], 1, app(IdentityConfig::class));
    }

    public function test_explicit_rich_fields_clear_nulls_and_redacted_metadata_without_changing_host_role(): void
    {
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->snapshot(['phone' => '+359888123456', 'organizationName' => 'Example', 'position' => 'Engineer', 'bio' => 'Biography', 'dateOfBirth' => '2000-02-29', 'gender' => 'other', 'country' => 'BG',
            'socialLinks' => ['site' => 'https://example.test/me'], 'profileCompleted' => true, 'adminNotes' => 'Migration note', 'tags' => ['review'], 'lastLoginAt' => '2026-11-01T10:00:00.000Z']));
        $user = RichNativeUser::firstOrFail();
        $this->assertSame('Europe/Sofia', $user->timezone);
        $this->assertSame('individual', $user->account_type);
        $this->assertSame('2000-02-29', $user->date_of_birth);
        $this->assertSame(['site' => 'https://example.test/me'], $user->social_links);
        $this->assertSame(['review'], $user->tags);
        $this->assertTrue($user->profile_completed);
        $repository->apply($this->snapshot([], 2));
        $user->refresh();
        foreach (['phone', 'organization_name', 'position', 'bio', 'date_of_birth', 'gender', 'country', 'social_links', 'admin_notes', 'last_login_at'] as $field) {
            $this->assertNull($user->getAttribute($field), $field);
        }
        $this->assertSame([], $user->tags);
        $this->assertSame('host-admin', $user->local_role);
        $this->assertSame('stale', $repository->apply($this->snapshot(['phone' => 'stale'], 1)));
        $this->assertNull($user->refresh()->phone);
    }

    public function test_unmapped_rich_fields_remain_owned_by_the_application(): void
    {
        $this->configure(['identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email']]);
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->snapshot());
        $user = RichNativeUser::firstOrFail();
        $user->update(['phone' => 'host phone', 'admin_notes' => 'host note']);
        $repository->apply($this->snapshot(['phone' => 'provider phone', 'adminNotes' => 'provider note'], 2));
        $this->assertSame('host phone', $user->refresh()->phone);
        $this->assertSame('host note', $user->admin_notes);
    }

    public function test_case_sensitive_iana_ids_include_icu_tzdb_aliases(): void
    {
        foreach (['UTC', 'Europe/Sofia', 'Asia/Calcutta', 'Europe/Kiev', 'America/Indianapolis'] as $timezone) {
            $this->assertSame($timezone, $this->snapshot(['timezone' => $timezone])->profile['timezone']);
        }
    }

    public function test_social_link_key_order_does_not_conflict_at_the_same_version(): void
    {
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->snapshot(['socialLinks' => ['one' => 'https://one.test', 'two' => 'https://two.test']]));
        $this->assertSame('unchanged', $repository->apply($this->snapshot(['socialLinks' => ['two' => 'https://two.test', 'one' => 'https://one.test']])));
    }

    public function test_multiline_profile_text_is_preserved(): void
    {
        app(UserSnapshotRepository::class)->apply($this->snapshot(['bio' => "First line\nSecond line", 'adminNotes' => "Private note\nSecond line"]));
        $user = RichNativeUser::firstOrFail();
        $this->assertSame("First line\nSecond line", $user->bio);
        $this->assertSame("Private note\nSecond line", $user->admin_notes);
    }

    public static function invalidFields(): array
    {
        return [
            ['timezone', []], ['timezone', 'not/a-zone'], ['timezone', 'utc'], ['timezone', 'europe/sofia'], ['timezone', '+02:00'], ['timezone', 'GMT+2'], ['accountType', 'admin'], ['phone', str_repeat('x', 33)], ['organizationName', str_repeat('x', 161)],
            ['position', str_repeat('x', 121)], ['bio', str_repeat('x', 2001)], ['dateOfBirth', '2001-02-29'], ['dateOfBirth', '2020-1-01'], ['dateOfBirth', '2999-01-01'],
            ['gender', 'unknown'], ['country', 'ZZ'], ['country', 'bg'], ['socialLinks', ['site' => 'http://example.test']], ['socialLinks', ['site' => 'https://user:pass@example.test']],
            ['socialLinks', ['https://example.test']], ['profileCompleted', 1], ['adminNotes', str_repeat('x', 5001)], ['tags', ['duplicate', 'duplicate']],
            ['tags', [str_repeat('x', 65)]], ['lastLoginAt', '2026-02-30T00:00:00Z'], ['lastLoginIp', '192.0.2.1'],
        ];
    }

    #[DataProvider('invalidFields')]
    public function test_invalid_rich_facts_are_rejected_before_persistence(string $field, mixed $value): void
    {
        $this->expectException(IdentityException::class);
        $this->snapshot([$field => $value]);
    }

    public function test_missing_required_profile_fact_is_rejected(): void
    {
        $profile = ProfileFixture::profile();
        unset($profile['phone']);
        $this->expectException(IdentityException::class);
        UserSnapshot::validate(['subject' => 'person', 'version' => 1, 'state' => 'active', 'profile' => $profile], 1, app(IdentityConfig::class));
    }
}
