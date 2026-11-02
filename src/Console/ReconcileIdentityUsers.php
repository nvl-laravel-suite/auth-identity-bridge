<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Console;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use Illuminate\Console\Command;

class ReconcileIdentityUsers extends Command
{
    protected $signature = 'identity:users-reconcile {--consumer= : Explicit registered consumer name} {--limit=100 : Maximum profiles per provider page and known-user batch} {--max-pages=1000 : Bounded reconciliation pages per invocation}';

    protected $description = 'Reconcile versioned identity profiles and recover durable refresh work';

    public function handle(Identity $identity): int
    {
        $limit = $this->option('limit');
        if (! is_scalar($limit) || ! ctype_digit((string) $limit)) {
            $this->error('user_sync_limit_invalid');

            return self::FAILURE;
        }
        try {
            $name = $this->option('consumer');
            if (! is_string($name) || $name === '') {
                throw new IdentityException('consumer_selection_required');
            }
            $manager = $identity->consumer($name)->make(UserSyncManager::class);
            $maximum = $this->option('max-pages');
            if (! is_scalar($maximum) || ! ctype_digit((string) $maximum) || (int) $maximum < 1 || (int) $maximum > 10000) {
                throw new IdentityException('user_sync_limit_invalid');
            }
            $totals = ['profiles' => 0, 'known' => 0, 'applied' => 0, 'stale' => 0, 'missing' => 0];
            $seen = [];
            for ($page = 0; $page < (int) $maximum; $page++) {
                $result = $manager->reconcile((int) $limit);
                foreach ($totals as $key => $count) {
                    $totals[$key] += $result[$key];
                }
                if ($result['completed'] || ($result['nextCursor'] === null && $result['knownCursor'] === null)) {
                    break;
                }
                $cursorKey = json_encode([$result['nextCursor'], $result['knownCursor']], JSON_THROW_ON_ERROR);
                if (isset($seen[$cursorKey])) {
                    throw new IdentityException('user_sync_cursor_not_advancing');
                }
                $seen[$cursorKey] = true;
            }
            $result = array_replace($result, $totals);
            $result['completed'] = $result['completed'] && $totals['missing'] === 0;

            $this->line(json_encode($result, JSON_THROW_ON_ERROR));

            return $result['completed'] ? self::SUCCESS : self::FAILURE;
        } catch (IdentityException $error) {
            $safe = ['consumer_selection_required', 'unknown_consumer', 'user_sync_disabled', 'user_sync_limit_invalid', 'user_sync_busy', 'user_sync_cursor_not_advancing', 'user_sync_native_pending', 'user_sync_policy_stale', 'user_sync_cursor_changed'];
            $this->error(in_array($error->errorCode, $safe, true) ? $error->errorCode : 'user_sync_unavailable');

            return self::FAILURE;
        } catch (\Throwable) {
            $this->error('user_sync_unavailable');

            return self::FAILURE;
        }
    }
}
