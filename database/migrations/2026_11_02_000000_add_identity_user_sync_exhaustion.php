<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::connection(config('identity.connection'))->table('identity_user_sync_bindings', function (Blueprint $table): void {
            $table->boolean('list_exhausted')->default(false);
            $table->boolean('known_exhausted')->default(false);
            $table->unsignedBigInteger('cycle_generation')->nullable();
            $table->unsignedBigInteger('cycle_policy_version')->nullable();
            $table->unsignedBigInteger('progress_version')->default(0);
        });
    }

    public function down(): void
    {
        Schema::connection(config('identity.connection'))->table('identity_user_sync_bindings', function (Blueprint $table): void {
            $table->dropColumn(['list_exhausted', 'known_exhausted', 'cycle_generation', 'cycle_policy_version', 'progress_version']);
        });
    }
};
