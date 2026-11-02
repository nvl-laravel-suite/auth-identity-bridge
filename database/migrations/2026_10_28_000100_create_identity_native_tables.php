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
        $schema->create('identity_user_links', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64);
            $table->uuid('projection_id');
            $table->string('user_type');
            $table->string('user_id');
            $table->string('owner_key', 64);
            $table->timestamps();
            $table->unique(['binding_hash', 'projection_id']);
            $table->unique(['binding_hash', 'owner_key']);
        });
        $schema->create('identity_local_profiles', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64);
            $table->string('owner_key', 64);
            $table->string('display_name')->nullable();
            $table->text('avatar')->nullable();
            $table->text('biography')->nullable();
            $table->string('locale', 35)->nullable();
            $table->string('timezone', 100)->nullable();
            $table->json('preferences');
            $table->unsignedBigInteger('version')->default(1);
            $table->timestamps();
            $table->unique(['binding_hash', 'owner_key']);
        });
    }

    public function down(): void
    {
        $schema = Schema::connection(config('identity.connection'));
        $schema->dropIfExists('identity_local_profiles');
        $schema->dropIfExists('identity_user_links');
    }
};
