<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\BoundSessionHandler;
use Illuminate\Session\ArraySessionHandler;
use PHPUnit\Framework\TestCase;

class BoundSessionHandlerTest extends TestCase
{
    public function test_swapped_php_pointer_cannot_read_overwrite_or_destroy_another_binding(): void
    {
        $this->assertTrue(class_exists(BoundSessionHandler::class), 'Bound framework store is missing');
        $shared = new ArraySessionHandler(120);
        $one = new BoundSessionHandler($shared, str_repeat('a', 64), true);
        $two = new BoundSessionHandler($shared, str_repeat('b', 64), false);
        $id = str_repeat('x', 40);
        $shared->write($id, 'legacy-one');
        $this->assertSame('legacy-one', $one->read($id));
        $one->write($id, 'valid-one');
        $this->assertSame('', $two->read($id));
        $two->write($id, 'valid-two');
        $this->assertSame('valid-one', $one->read($id));
        $two->destroy($id);
        $this->assertSame('valid-one', $one->read($id));
        try {
            (new BoundSessionHandler($shared, str_repeat('b', 64), true))->write($id, 'wrong-default');
            $this->fail('A changed default overwrote a marked row');
        } catch (IdentityException $error) {
            $this->assertSame('session_binding_failed', $error->errorCode);
        }
        $this->assertSame('valid-one', $one->read($id));
    }
}
