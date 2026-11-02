<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSnapshot;
use IdentityPlatform\Laravel\Sync\UserSnapshotClient;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeMappingDefinition;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use IdentityPlatform\Laravel\Users\Transforms\ArrayValue;
use IdentityPlatform\Laravel\Users\Transforms\EnumValue;
use IdentityPlatform\Laravel\Users\Transforms\LifecycleBoolean;
use IdentityPlatform\Laravel\Users\Transforms\NullableDate;
use IdentityPlatform\Laravel\Users\Transforms\NullableTimestamp;
use IdentityPlatform\Laravel\Users\Transforms\SafeAvatar;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

enum NativeGender: string
{
    case Female = 'female';
    case Male = 'male';
}
class UUIDProjectionUser extends User
{
    use HasUuids;

    protected $table = 'uuid_projection_users';

    protected $primaryKey = 'person_uuid';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['birth' => 'immutable_date', 'tags_json' => 'array', 'enabled' => 'boolean', 'gender_code' => NativeGender::class];
    }
}
class NativeMappingDefinitionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('uuid_projection_users', function (Blueprint $t): void {
            $t->uuid('person_uuid')->primary();
            $t->string('display');
            $t->string('contact');
            $t->date('birth')->nullable();
            $t->timestamp('seen_at')->nullable();
            $t->json('tags_json')->nullable();
            $t->string('gender_code')->nullable();
            $t->boolean('enabled')->default(false);
            $t->text('portrait')->nullable();
            $t->string('business')->default('owned');
            $t->timestamps();
        });
    }

    private function configureMapping(): void
    {
        $this->configure(['identity.consumers.one.users.model' => UUIDProjectionUser::class, 'identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.provision_missing' => true, 'identity.consumers.one.users.fields' => ['name' => 'display', 'email' => 'contact', 'state' => ['column' => 'enabled', 'transform' => LifecycleBoolean::class, 'cast' => 'boolean'], 'dateOfBirth' => ['column' => 'birth', 'transform' => NullableDate::class, 'cast' => 'immutable_date'], 'lastLoginAt' => ['column' => 'seen_at', 'transform' => NullableTimestamp::class, 'cast' => 'immutable_datetime'], 'tags' => ['column' => 'tags_json', 'transform' => ArrayValue::class, 'cast' => 'array'], 'gender' => ['column' => 'gender_code', 'transform' => EnumValue::class, 'options' => ['enum' => NativeGender::class], 'cast' => NativeGender::class], 'picture' => ['column' => 'portrait', 'transform' => SafeAvatar::class]], 'identity.consumers.one.users.local_fields' => ['business']]);
    }

    public function test_uuid_schema_transforms_unicode_null_and_redaction_preserve_native_identity_and_business_fields(): void
    {
        $this->configureMapping();
        $repo = app(UserSnapshotRepository::class);
        $record = ['subject' => 'person', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile(['name' => 'Иван 🦊', 'dateOfBirth' => '2000-02-29', 'gender' => 'female', 'tags' => ['тест'], 'lastLoginAt' => '2026-10-01T12:00:00.000Z', 'picture' => 'https://images.example.test/a.png'])];
        $repo->apply(UserSnapshot::validate($record, 1, app(IdentityConfig::class)));
        $user = UUIDProjectionUser::firstOrFail();
        $key = $user->getKey();
        $this->assertIsString($key);
        $this->assertSame('Иван 🦊', $user->display);
        $this->assertSame('2000-02-29', $user->birth->format('Y-m-d'));
        $this->assertSame(['тест'], $user->tags_json);
        $this->assertSame(NativeGender::Female, $user->gender_code);
        $this->assertTrue($user->enabled);
        $this->assertSame('owned', $user->business);
        $record['version'] = 2;
        $record['state'] = 'suspended';
        $record['profile'] = ProfileFixture::profile(['name' => 'Иван 🦊']);
        $repo->apply(UserSnapshot::validate($record, 2, app(IdentityConfig::class)));
        $user->refresh();
        $this->assertSame($key, $user->getKey());
        $this->assertNull($user->birth);
        $this->assertNull($user->seen_at);
        $this->assertSame([], $user->tags_json);
        $this->assertFalse($user->enabled);
        $this->assertSame('owned', $user->business);
    }

    public function test_omitted_jit_facts_do_not_clear_host_values(): void
    {
        $this->configureMapping();
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Name', 'email' => 'a@example.test']);
        $user = app(IdentityUserResolver::class)->resolve($projection);
        $user->update(['birth' => '1999-01-01']);
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'New']);
        app(NativeUserMapper::class)->synchronize($user, $projection);
        $this->assertSame('1999-01-01', $user->refresh()->birth->format('Y-m-d'));
    }

    public static function invalidMappings(): array
    {
        return [['person_uuid'], ['organization_id'], ['password'], ['remember_token'], ['business'], [['column' => 'display', 'transform' => \stdClass::class]], [['column' => 'display', 'cast' => 'object']], [['column' => 'display', 'transform' => EnumValue::class, 'options' => ['enum' => \stdClass::class]]]];
    }

    #[DataProvider('invalidMappings')]
    public function test_invalid_mapping_is_rejected_during_configuration(mixed $field): void
    {
        $this->expectException(IdentityException::class);
        $this->configure(['identity.consumers.one.users.model' => UUIDProjectionUser::class, 'identity.consumers.one.users.fields' => ['name' => $field], 'identity.consumers.one.users.local_fields' => ['business']]);
    }

    public function test_actual_foreign_key_is_preserved_even_with_unconventional_name(): void
    {
        Schema::create('organizations', fn (Blueprint $t) => $t->id());
        Schema::table('uuid_projection_users', function (Blueprint $t): void {
            $t->unsignedBigInteger('tenant')->nullable();
            $t->foreign('tenant')->references('id')->on('organizations');
        });
        $definition = new NativeMappingDefinition(['fields' => ['name' => 'tenant']], new UUIDProjectionUser);
        $this->expectException(IdentityException::class);
        $definition->values(['name' => 1], new UUIDProjectionUser);
    }

    public function test_existing_native_factory_result_cannot_exchange_accounts(): void
    {
        $this->configureMapping();
        $existing = UUIDProjectionUser::create(['display' => 'Existing', 'contact' => 'existing@example.test']);
        $this->nativeFactory(fn () => $existing);
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Person', 'email' => 'person@example.test']);
        try {
            app(IdentityUserResolver::class)->resolve($projection);
            $this->fail('Existing factory row linked');
        } catch (IdentityException $e) {
            $this->assertSame('identity_user_invalid', $e->errorCode);
        }$this->assertDatabaseCount('identity_user_links', 0);
        $this->assertSame('Existing', $existing->refresh()->display);
    }

    public function test_invalid_native_destination_fails_preflight_before_worker_http(): void
    {
        $this->configureMapping();
        $this->configure(['identity.consumers.one.users.fields.name' => 'missing_display_column']);
        Http::preventStrayRequests();
        try {
            app(UserSnapshotClient::class)->read(['person']);
            $this->fail('Invalid schema contacted provider');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_mapping_invalid', $error->errorCode);
        }
        Http::assertNothingSent();
    }

    public static function authorityDestinations(): array
    {
        return array_map(fn ($column) => [$column], ['role', 'permission', 'role_name', 'permission_level', 'is_super_admin', 'is_superuser', 'is_staff', 'privilege_level', 'two_factor_recovery_codes', 'two_factor_enabled', 'mfa_enabled', 'totp_seed', 'security_stamp', 'authentication_level', 'isActive']);
    }

    #[DataProvider('authorityDestinations')]
    public function test_actual_authority_columns_cannot_be_assigned_by_profile_mapping(string $column): void
    {
        Schema::table('uuid_projection_users', fn (Blueprint $table) => $table->string($column)->default('host-owned'));
        $user = UUIDProjectionUser::create(['display' => 'Existing', 'contact' => 'existing@example.test']);
        Http::preventStrayRequests();
        try {
            // Empty host declarations cannot override the mandatory reserved destinations.
            $definition = new NativeMappingDefinition(['fields' => ['name' => $column], 'protected_fields' => [], 'local_fields' => [], 'readonly_fields' => []], $user);
            $user->forceFill($definition->values(['name' => 'super-admin'], $user))->save();
            $this->fail('Profile assigned a native authority column');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_mapping_invalid', $error->errorCode);
        }
        $this->assertSame('host-owned', $user->refresh()->getAttribute($column));
        Http::assertNothingSent();
    }

    public static function lifecycleFlags(): array
    {
        return [['active'], ['is_active'], ['enabled'], ['is_enabled'], ['account_active'], ['login_enabled']];
    }

    #[DataProvider('lifecycleFlags')]
    public function test_nonlifecycle_facts_cannot_drive_native_active_flags(string $column): void
    {
        if ($column !== 'enabled') {
            Schema::table('uuid_projection_users', fn (Blueprint $table) => $table->boolean($column)->default(false));
        }
        $user = UUIDProjectionUser::create(['display' => 'Existing', 'contact' => 'existing@example.test']);
        Http::preventStrayRequests();
        try {
            $this->configure(['identity.consumers.one.users.model' => UUIDProjectionUser::class, 'identity.consumers.one.users.fields' => ['profileCompleted' => ['column' => $column, 'cast' => 'boolean']]]);
            $this->fail('Nonlifecycle active flag passed configuration');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_mapping_invalid', $error->errorCode);
        }
        $this->assertFalse((bool) $user->refresh()->getAttribute($column));
        Http::assertNothingSent();
    }

    public function test_unshared_explicit_lifecycle_flag_maps_and_shared_destination_refuses(): void
    {
        Schema::table('uuid_projection_users', fn (Blueprint $table) => $table->boolean('is_active')->default(false));
        $user = UUIDProjectionUser::create(['display' => 'Existing', 'contact' => 'existing@example.test']);
        $users = ['fields' => ['state' => ['column' => 'is_active', 'transform' => LifecycleBoolean::class, 'cast' => 'boolean']]];
        $mapping = new NativeMappingDefinition($users, $user);
        $user->forceFill($mapping->values(['state' => 'active'], $user))->save();
        $this->assertTrue((bool) $user->refresh()->is_active);
        $user->forceFill($mapping->values(['state' => 'suspended'], $user))->save();
        $this->assertFalse((bool) $user->refresh()->is_active);
        $this->expectExceptionObject(new IdentityException('identity_user_mapping_invalid', 503));
        new NativeMappingDefinition($users + ['native_group' => ['name' => 'people', 'writer' => 'one', 'epoch' => 1]], $user);
    }

    public static function privilegeFlags(): array
    {
        return [['is_super_admin'], ['two_factor_enabled'], ['mfa_enabled']];
    }

    #[DataProvider('privilegeFlags')]
    public function test_profile_completion_cannot_set_privilege_or_mfa_boolean_columns(string $column): void
    {
        Schema::table('uuid_projection_users', fn (Blueprint $table) => $table->boolean($column)->default(false));
        $user = UUIDProjectionUser::create(['display' => 'Existing', 'contact' => 'existing@example.test']);
        try {
            $definition = new NativeMappingDefinition(['fields' => ['profileCompleted' => ['column' => $column, 'cast' => 'boolean']]], $user);
            $user->forceFill($definition->values(['profileCompleted' => true], $user))->save();
            $this->fail('Profile completion set a privilege/MFA flag');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_mapping_invalid', $error->errorCode);
        }
        $this->assertFalse((bool) $user->refresh()->getAttribute($column));
    }
}
