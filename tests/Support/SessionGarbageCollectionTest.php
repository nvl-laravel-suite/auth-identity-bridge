<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

use IdentityPlatform\Laravel\Support\ConsumerContext;
use IdentityPlatform\Laravel\Support\ConsumerSessionManager;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class SessionGarbageCollectionTest extends TestCase
{
    public static function backends(): array
    {
        return [['file'], ['database']];
    }

    #[DataProvider('backends')]
    public function test_short_lifetime_gc_only_deletes_its_own_expired_sessions(string $driver): void
    {
        Schema::create('shared_framework_sessions', function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->text('payload');
            $table->integer('last_activity');
            $table->string('user_id')->nullable();
            $table->string('ip_address')->nullable();
            $table->text('user_agent')->nullable();
        });
        $definition = config('identity.consumers.one');
        $definition['session']['driver'] = $driver;
        $definition['session']['table'] = 'shared_framework_sessions';
        $definition['session']['connection'] = config('database.default');
        $definition['session']['lifetime'] = 120;
        $one = new ConsumerContext('one', $definition, config('database.default'));
        config(['session' => $one->sessionSettings()]);
        $first = (new ConsumerSessionManager($this->app, $one, true))->driver()->getHandler();
        $definition['browser']['client_id'] = 'web-2';
        $definition['session']['lifetime'] = 1;
        $definition['local']['idle_seconds'] = 30;
        $definition['local']['absolute_seconds'] = 60;
        $two = new ConsumerContext('two', $definition, config('database.default'));
        config(['session' => $two->sessionSettings()]);
        $second = (new ConsumerSessionManager($this->app, $two, false))->driver()->getHandler();
        $first->write('valid-first', 'first-data');
        $first->setExists(false);
        $first->write('expired-first', 'expired-first-data');
        $second->write('expired-second', 'second-data');
        $secondKey = 'identity:'.$two->bindingHash().':expired-second';
        $ages = ['valid-first' => 300, 'expired-first' => 10000, $secondKey => 300, 'unowned' => 10000];
        if ($driver === 'database') {
            DB::table('shared_framework_sessions')->insert(['id' => 'unowned', 'payload' => base64_encode('not-package-data'), 'last_activity' => time()]);
            foreach ($ages as $key => $age) {
                DB::table('shared_framework_sessions')->where('id', $key)->update(['last_activity' => time() - $age]);
            }
        } else {
            $path = $one->sessionSettings()['files'];
            file_put_contents($path.'/unowned', 'not-package-data');
            foreach ($ages as $key => $age) {
                touch($path.'/'.$key, time() - $age);
            }
        }
        $this->assertSame(1, $second->gc(60));
        $this->assertSame('first-data', $first->read('valid-first'));
        $this->assertSame(1, $first->gc(7200));
        $this->assertSame('first-data', $first->read('valid-first'));
        if ($driver === 'database') {
            $this->assertSame(1, DB::table('shared_framework_sessions')->where('id', 'unowned')->count());
        } else {
            $this->assertSame('not-package-data', file_get_contents($path.'/unowned'));
        }
    }
}
