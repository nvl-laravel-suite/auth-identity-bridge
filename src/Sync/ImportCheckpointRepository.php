<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class ImportCheckpointRepository
{
    public function __construct(private IdentityConfig $config, private UserSyncWorkRepository $work, private UserSnapshotRepository $snapshots) {}

    public function assertStandalone(): void
    {
        Contract::require((new ImportRun)->getConnection()->transactionLevel() === 0, 'user_sync_outer_transaction_unsupported', 409);
    }

    public function checkSource(ImportRun $run, string $sourceId): void
    {
        $bindingId = hash('sha256', $this->config->bindingHash()."\0".$sourceId);
        $existing = ImportEntry::query()->where('run_id', $run->id)->where('import_binding_id', $bindingId)->first();
        Contract::require(! $existing || $existing->page_id === hash('sha256', $run->id."\0".($run->cursor ?? '')), 'user_import_duplicate_source', 409);
    }

    public function knownSubject(string $bindingId): bool
    {
        return ImportBinding::findOrFail($bindingId)->subject !== null;
    }

    public function open(string $source, string $class, ?string $resume, int $limit): ImportRun
    {
        if ($resume !== null) {
            $run = ImportRun::find($resume);
            Contract::require($run && $run->binding_hash === $this->config->bindingHash() && $run->consumer_name === $this->config->context()->name() && $run->source_name === $source && $run->source_class === $class && $run->batch_size === $limit, 'user_import_run_invalid', 409);

            return $run;
        }

        return ImportRun::create(['id' => (string) Str::uuid(), 'binding_hash' => $this->config->bindingHash(), 'consumer_name' => $this->config->context()->name(), 'source_name' => $source, 'source_class' => $class, 'batch_size' => $limit]);
    }

    /**
     * @param  list<array{id: string, binding_hash: string, source_name: string, source_user_id: string, native_user_id: string, native_type: class-string<Model>, physical_key: string}>  $references
     */
    public function reserve(ImportRun $run, array $references, ?string $next): ImportPage
    {
        return $run->getConnection()->transaction(function () use ($run, $references, $next): ImportPage {
            $this->current($run);
            $pageId = hash('sha256', $run->id."\0".($run->cursor ?? ''));
            $page = ImportPage::find($pageId);
            if ($page) {
                Contract::require(! $page->finished && $page->next_cursor === $next, 'user_import_cursor_invalid', 409);
                $recorded = ImportEntry::query()->where('page_id', $pageId)->orderBy('position')->pluck('import_binding_id')->all();
                Contract::require($recorded === array_column($references, 'id'), 'user_import_binding_changed', 409);
            } else {
                $page = ImportPage::create(['id' => $pageId, 'run_id' => $run->id, 'next_cursor' => $next]);
            }
            foreach ($references as $position => $reference) {
                $entryId = hash('sha256', $run->id."\0".$reference['id']);
                $entry = ImportEntry::find($entryId);
                Contract::require(! $entry || $entry->page_id === $pageId, 'user_import_duplicate_source', 409);
                $binding = ImportBinding::query()->createOrFirst(['id' => $reference['id']], $reference);
                foreach ($reference as $key => $value) {
                    Contract::require($binding->{$key} === $value, 'user_import_binding_changed', 409);
                }
                if (! $entry) {
                    ImportEntry::create(['id' => $entryId, 'run_id' => $run->id, 'page_id' => $pageId, 'import_binding_id' => $binding->id, 'position' => $position]);
                }
            }
            $run->update(['status' => 'pending', 'error_code' => null]);

            return $page;
        });
    }

    public function attempting(ImportRun $run): void
    {
        $run->getConnection()->transaction(function () use ($run): void {
            $this->current($run);
            $run->update(['remote_status' => 'unknown', 'accepted_in_last_attempt' => 0]);
        });
    }

    /** Save only IDs, then request durable fresh work. No response bodies or credentials persist here.
     *
     * @return array<array-key, UserSyncRequest>
     */
    public function accepted(ImportRun $run, UserImportResult $result): array
    {
        return $run->getConnection()->transaction(function () use ($run, $result): array {
            $this->current($run);
            $run->update(['remote_status' => 'accepted', 'accepted_in_last_attempt' => count($result->mappings)]);
            $work = [];
            foreach ($result->mappings as $mapping) {
                $row = ImportBinding::query()->whereKey(hash('sha256', $this->config->bindingHash()."\0".$mapping->sourceUserId))->lockForUpdate()->firstOrFail();
                Contract::require($row->subject === null || $row->subject === $mapping->snapshot->subject, 'user_import_binding_changed', 409);
                $row->update(['subject' => $mapping->snapshot->subject, 'status' => 'imported']);
                $work[$mapping->sourceUserId] = $this->work->request($mapping->snapshot->subject);
            }

            return $work;
        });
    }

    /**
     * @param  list<string>  $outcomes
     * @param  array<array-key, UserSyncRequest>  $work
     */
    public function finish(ImportRun $run, ImportPage $page, UserImportResult $result, array $outcomes, array $work): void
    {
        $run->getConnection()->transaction(function () use ($run, $page, $result, $outcomes, $work): void {
            $this->current($run);
            foreach ($result->mappings as $index => $mapping) {
                $id = hash('sha256', $this->config->bindingHash()."\0".$mapping->sourceUserId);
                $pending = $outcomes[$index] === 'native_pending' || $this->snapshots->nativePending($mapping->snapshot->subject) > 0;
                ImportBinding::query()->whereKey($id)->update(['associated' => true, 'status' => $pending ? 'native_pending' : 'applied']);
                ImportEntry::query()->where('run_id', $run->id)->where('import_binding_id', $id)->update(['outcome' => $pending ? 'native_pending' : $outcomes[$index]]);
                if (! $pending) {
                    $this->work->complete($work[$mapping->sourceUserId]);
                }
            }
            $this->advance($run, $page);
        });
    }

    public function advance(ImportRun $run, ImportPage $page): void
    {
        $run->getConnection()->transaction(function () use ($run, $page): void {
            $this->current($run);
            Contract::require($page->run_id === $run->id && $page->id === hash('sha256', $run->id."\0".($run->cursor ?? '')) && ! $page->refresh()->finished, 'user_import_run_changed', 409);
            $page->update(['finished' => true]);
            $run->update(['cursor' => $page->next_cursor, 'exhausted' => $page->next_cursor === null, 'status' => 'pending', 'error_code' => null]);
        });
    }

    public function failed(ImportRun $run, string $code, string $remoteOutcome, int $accepted): void
    {
        ImportRun::query()->whereKey($run->id)->where('cursor', $run->cursor)->where('exhausted', false)->update(['status' => 'failed', 'error_code' => $code, 'remote_status' => $remoteOutcome, 'accepted_in_last_attempt' => $accepted]);
    }

    private function current(ImportRun $expected): void
    {
        $current = ImportRun::query()->whereKey($expected->id)->lockForUpdate()->firstOrFail();
        Contract::require($current->binding_hash === $this->config->bindingHash() && $current->cursor === $expected->cursor && ! $current->exhausted, 'user_import_run_changed', 409);
    }

    /**
     * @return array{imported: int, associated: int, unresolvedImports: int}
     */
    public function bindingCounts(): array
    {
        $links = UserImportLink::query()->where('binding_hash', $this->config->bindingHash());
        $associated = (clone $links)->count();
        $imported = ImportBinding::query()->where('binding_hash', $this->config->bindingHash())->whereNotNull('subject')->whereNotIn('id', (clone $links)->select('id'))->count();

        return ['imported' => $associated + $imported, 'associated' => $associated, 'unresolvedImports' => $this->unresolved()];
    }

    private function unresolved(): int
    {
        $appliedSubjects = UserSyncState::query()->where('binding_hash', $this->config->bindingHash())->where('native_status', 'applied')->whereColumn('native_version', 'version')->select('subject');

        return ImportBinding::query()->where('binding_hash', $this->config->bindingHash())->where(function ($query) use ($appliedSubjects): void {
            $query->whereNotIn('id', UserImportLink::query()->where('binding_hash', $this->config->bindingHash())->select('id'))->orWhereNull('subject')->orWhereNotIn('subject', $appliedSubjects);
        })->count();
    }

    /**
     * @return array{runId: string, imported: int, associated: int, applied: int, stale: int, missing: int, pending: int, nativePending: int, unresolved: int, failed: int, error: string|null, exhausted: bool, completed: bool}
     */
    public function summary(ImportRun $run): array
    {
        $run->refresh();
        $ids = ImportEntry::query()->where('run_id', $run->id)->select('import_binding_id');
        $rows = ImportBinding::query()->whereIn('id', $ids);
        $bindingWork = $this->work->bindingRequest();
        $pending = $this->work->pendingCount() + ($bindingWork && $bindingWork->completed_generation < $bindingWork->generation ? 1 : 0);
        $nativePending = $this->snapshots->nativePending();
        $unresolved = $this->unresolved();
        $completed = $run->exhausted && $pending === 0 && $nativePending === 0 && $unresolved === 0 && $run->error_code === null;

        return ['runId' => $run->id, 'imported' => (clone $rows)->whereNotNull('subject')->count(), 'associated' => UserImportLink::query()->whereIn('id', (clone $rows)->select('id'))->count(),
            'applied' => ImportEntry::query()->where('run_id', $run->id)->whereIn('outcome', ['applied', 'unchanged'])->count(),
            'stale' => ImportEntry::query()->where('run_id', $run->id)->where('outcome', 'stale')->count(), 'missing' => $run->error_code === 'user_import_native_missing' ? 1 : 0,
            'pending' => $pending, 'nativePending' => $nativePending, 'unresolved' => $unresolved, 'failed' => $run->error_code !== null ? 1 : 0, 'error' => $run->error_code, 'exhausted' => $run->exhausted, 'completed' => $completed];
    }
}
