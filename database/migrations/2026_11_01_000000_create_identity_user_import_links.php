<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::connection(config('identity.connection'))->create('identity_user_import_links', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64);
            $table->string('source_user_id', 128);
            $table->string('issuer');
            $table->string('subject', 128);
            $table->uuid('projection_id');
            $table->string('owner_key', 64);
            $table->timestamps();
            $table->unique(['binding_hash', 'source_user_id']);
            $table->unique(['binding_hash', 'subject']);
            $table->unique(['binding_hash', 'owner_key']);
        });
    }

    public function down(): void
    {
        Schema::connection(config('identity.connection'))->dropIfExists('identity_user_import_links');
    }
};
