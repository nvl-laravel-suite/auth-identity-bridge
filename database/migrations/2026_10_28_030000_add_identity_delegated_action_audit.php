<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::connection(config('identity.connection'))->table('identity_delegated_actions', function (Blueprint $table): void {
            $table->string('actor_id', 128);
            $table->string('subject_id', 128);
            $table->string('organization_id', 128)->nullable();
            $table->string('resource_type', 128);
            $table->string('resource_id', 256);
            $table->json('audit');
        });
    }

    public function down(): void
    {
        Schema::connection(config('identity.connection'))->table('identity_delegated_actions', function (Blueprint $table): void {
            $table->dropColumn(['actor_id', 'subject_id', 'organization_id', 'resource_type', 'resource_id', 'audit']);
        });
    }
};
