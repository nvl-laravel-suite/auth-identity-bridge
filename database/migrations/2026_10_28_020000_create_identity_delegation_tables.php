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
        $schema->create('identity_delegations', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64)->index();
            $table->string('source_sid', 128);
            $table->string('status', 16);
            $table->string('browser_binding', 128);
            $table->unsignedBigInteger('context_version');
            $table->text('handle_vault')->nullable();
            $table->json('decision')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
        $schema->create('identity_delegated_actions', function (Blueprint $table): void {
            $table->string('id', 128)->primary();
            $table->string('binding_hash', 64)->index();
            $table->string('session_id', 64)->index();
            $table->string('delegation_id', 128)->index();
            $table->string('operation', 128);
            $table->string('command_digest', 64);
            $table->text('receipt_vault');
            $table->string('outcome', 16);
            $table->json('result')->nullable();
            $table->timestamp('reported_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        $schema = Schema::connection(config('identity.connection'));
        $schema->dropIfExists('identity_delegated_actions');
        $schema->dropIfExists('identity_delegations');
    }
};
