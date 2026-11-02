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
            $table->text('list_cursor')->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::connection(config('identity.connection'))->table('identity_user_sync_bindings', function (Blueprint $table): void {
            $table->string('list_cursor', 128)->nullable()->change();
        });
    }
};
