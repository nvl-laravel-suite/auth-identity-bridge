<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::connection(config('identity.connection'))->table('identity_sessions', fn (Blueprint $table) => $table->json('application_context')->nullable());
    }

    public function down(): void
    {
        Schema::connection(config('identity.connection'))->table('identity_sessions', fn (Blueprint $table) => $table->dropColumn('application_context'));
    }
};
