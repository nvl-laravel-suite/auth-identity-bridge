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
        $schema->create('identity_import_runs', function (Blueprint $table): void {
            $table->string('id', 36)->primary();
            $table->string('binding_hash', 64)->index();
            $table->string('consumer_name', 64);
            $table->string('source_name', 64);
            $table->string('source_class');
            $table->unsignedSmallInteger('batch_size');
            $table->text('cursor')->nullable();
            $table->boolean('exhausted')->default(false);
            $table->string('status', 32)->default('pending');
            $table->string('error_code', 80)->nullable();
            $table->string('remote_status', 32)->default('not_attempted');
            $table->unsignedSmallInteger('accepted_in_last_attempt')->default(0);
            $table->timestamps();
        });
        $schema->create('identity_import_pages', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('run_id', 36)->index();
            $table->text('next_cursor')->nullable();
            $table->boolean('finished')->default(false);
            $table->timestamps();
        });
        $schema->create('identity_import_bindings', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('binding_hash', 64)->index();
            $table->string('source_name', 64);
            $table->string('source_user_id', 255);
            $table->string('native_user_id', 255);
            $table->string('native_type');
            $table->string('physical_key', 64);
            $table->string('subject', 255)->nullable();
            $table->boolean('associated')->default(false);
            $table->string('status', 32)->default('reserved');
            $table->timestamps();
            $table->unique(['binding_hash', 'physical_key']);
        });
        $schema->create('identity_import_entries', function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('run_id', 36)->index();
            $table->string('page_id', 64)->index();
            $table->string('import_binding_id', 64);
            $table->unsignedSmallInteger('position');
            $table->string('outcome', 32)->default('pending');
            $table->timestamps();
            $table->unique(['run_id', 'import_binding_id']);
        });
    }

    public function down(): void
    {
        $schema = Schema::connection(config('identity.connection'));
        foreach (['identity_import_entries', 'identity_import_bindings', 'identity_import_pages', 'identity_import_runs'] as $table) {
            $schema->dropIfExists($table);
        }
    }
};
