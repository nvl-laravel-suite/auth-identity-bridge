<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $schema = Schema::connection(config('identity.connection'));
        $schema->table('identity_user_sync_states', function (Blueprint $t): void {
            $t->unsignedBigInteger('native_version')->default(0);
            $t->string('native_status', 24)->default('pending');
            $t->string('native_error', 64)->nullable();
        });
        $schema->create('identity_projection_owners', function (Blueprint $t): void {
            $t->string('id', 64)->primary();
            $t->string('kind', 16);
            $t->string('writer_binding', 64);
            $t->unsignedBigInteger('epoch');
            $t->string('identity_key', 64);
            $t->string('group_name', 64)->nullable();
            $t->timestamps();
        });
        $schema->table('identity_user_sync_states', function (Blueprint $t): void {
            $t->json('jit_profile')->nullable();
        });
    }

    public function down(): void
    {
        $schema = Schema::connection(config('identity.connection'));
        $schema->table('identity_user_sync_states', fn (Blueprint $t) => $t->dropColumn(['native_version', 'native_status', 'native_error', 'jit_profile']));
        $schema->dropIfExists('identity_projection_owners');
    }
};
