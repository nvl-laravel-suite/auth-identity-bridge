<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::connection(config('identity.connection'))->create('identity_consumer_commands', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64)->index();
            $table->json('reference');
            $table->string('state', 16)->default('retained');
            $table->json('receipt')->nullable();
            $table->string('refresh', 24)->default('pending');
            $table->string('sync_request_id', 64)->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::connection(config('identity.connection'))->dropIfExists('identity_consumer_commands');
    }
};
