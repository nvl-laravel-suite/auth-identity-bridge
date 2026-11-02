<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Http\Request;
use Illuminate\Session\ExistenceAwareInterface;
use SessionHandlerInterface;

/** Shared stores never address another consumer's row, even for a valid swapped cookie. */
final class BoundSessionHandler implements ExistenceAwareInterface, SessionHandlerInterface
{
    public function __construct(private SessionHandlerInterface $handler, private string $binding, private bool $preserveDefaultNamespace, private ?SessionGarbageCollector $garbage = null) {}

    private function key(string $id): string
    {
        return $this->preserveDefaultNamespace ? $id : 'identity:'.$this->binding.':'.$id;
    }

    public function open(string $path, string $name): bool
    {
        return $this->handler->open($path, $name);
    }

    public function close(): bool
    {
        return $this->handler->close();
    }

    public function read(string $id): string|false
    {
        $data = $this->handler->read($this->key($id));
        if (! is_string($data) || ! str_starts_with($data, 'identity-session.v1:')) {
            return $data;
        }
        $prefix = 'identity-session.v1:'.$this->binding."\n";
        if (! str_starts_with($data, $prefix)) {
            throw new IdentityException('session_binding_failed', 401);
        }

        return substr($data, strlen($prefix));
    }

    public function write(string $id, string $data): bool
    {
        $this->read($id);

        return $this->handler->write($this->key($id), 'identity-session.v1:'.$this->binding."\n".$data);
    }

    public function destroy(string $id): bool
    {
        $this->read($id);

        return $this->handler->destroy($this->key($id));
    }

    public function gc(int $max_lifetime): int|false
    {
        return $this->garbage?->collect($max_lifetime) ?? 0;
    }

    public function setExists($value): void
    {
        if ($this->handler instanceof ExistenceAwareInterface) {
            $this->handler->setExists($value);
        }
    }

    public function setRequest(Request $request): void
    {
        if (method_exists($this->handler, 'setRequest')) {
            $this->handler->setRequest($request);
        }
    }
}
