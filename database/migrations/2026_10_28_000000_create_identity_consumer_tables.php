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
        $schema->create('identity_users', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('identity_key', 64)->unique();
            $table->text('issuer');
            $table->string('subject');
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->text('picture')->nullable();
            $table->boolean('email_verified')->default(false);
            $table->timestamp('synchronized_at')->nullable();
            $table->timestamps();
        });
        $schema->create('identity_sessions', function (Blueprint $table) {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64)->index();
            $table->uuid('user_id')->nullable();
            $table->string('subject')->index();
            $table->string('sid')->index();
            $table->text('token_vault');
            $table->json('selection');
            $table->json('snapshot')->nullable();
            $table->unsignedBigInteger('context_version')->default(1);
            $table->unsignedBigInteger('token_generation')->default(1);
            $table->timestamp('started_at');
            $table->timestamp('last_activity_at');
            $table->timestamp('expires_at')->index();
            $table->timestamps();
        });
        $schema->create('identity_logins', function (Blueprint $table) {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64)->index();
            $table->string('browser_hash', 64);
            $table->text('intent');
            $table->string('protocol', 16);
            $table->timestamp('expires_at')->index();
            $table->timestamps();
        });
        $schema->create('identity_inbox', function (Blueprint $table) {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64)->index();
            $table->string('protocol', 32);
            $table->string('message_id');
            $table->string('body_hash', 64);
            $table->timestamp('received_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        $schema = Schema::connection(config('identity.connection'));
        foreach (['identity_inbox', 'identity_logins', 'identity_sessions', 'identity_users'] as $table) {
            $schema->dropIfExists($table);
        }
    }
};
