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
        $schema->create('identity_user_sync_bindings', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->unsignedBigInteger('policy_version')->default(0);
            $table->string('list_cursor', 128)->nullable();
            $table->string('known_cursor', 128)->nullable();
            $table->timestamps();
        });
        $schema->create('identity_user_sync_states', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64)->index();
            $table->text('issuer');
            $table->string('subject', 128);
            $table->uuid('projection_id')->index();
            $table->unsignedBigInteger('version')->default(0);
            $table->unsignedBigInteger('policy_version')->default(0);
            $table->string('state', 16)->default('pending');
            $table->string('digest', 64)->nullable();
            $table->json('profile')->nullable();
            $table->timestamp('synchronized_at')->nullable();
            $table->timestamps();
            $table->unique(['binding_hash', 'subject']);
        });
        $schema->create('identity_user_sync_requests', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64)->index();
            $table->text('issuer');
            $table->string('subject', 128);
            $table->string('kind', 16)->default('subject');
            $table->unsignedBigInteger('generation')->default(1);
            $table->unsignedBigInteger('completed_generation')->default(0);
            $table->unsignedInteger('attempts')->default(0);
            $table->string('last_error', 64)->nullable();
            $table->timestamp('next_attempt_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        $schema = Schema::connection(config('identity.connection'));
        foreach (['identity_user_sync_requests', 'identity_user_sync_states', 'identity_user_sync_bindings'] as $table) {
            $schema->dropIfExists($table);
        }
    }
};
