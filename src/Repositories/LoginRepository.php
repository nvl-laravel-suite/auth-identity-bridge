<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Repositories;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityLogin;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;

class LoginRepository
{
    public function __construct(private IdentityConfig $config, private IdentityVault $vault) {}

    /** @param array<array-key, mixed> $intent */
    public function create(string $browserId, array $intent, string $protocol): string
    {
        $state = bin2hex(random_bytes(32));
        $id = hash('sha256', $state);
        IdentityLogin::create(['id' => $id, 'binding_hash' => $this->config->bindingHash(), 'browser_hash' => hash('sha256', $browserId), 'intent' => $this->vault->seal($intent + ['state' => $state], 'intent:'.$id), 'protocol' => $protocol, 'expires_at' => now()->addSeconds(min(300, (int) $this->config->value('local.transaction_seconds', 300)))]);

        return $state;
    }

    /** @return array<array-key, mixed> */
    public function consume(string $state, string $browserId, string $protocol): array
    {
        if (! preg_match('/^[a-f0-9]{64}$/D', $state)) {
            throw new IdentityException('invalid_login_state', 401);
        }
        $id = hash('sha256', $state);
        $query = IdentityLogin::whereKey($id)->where('binding_hash', $this->config->bindingHash())->where('browser_hash', hash('sha256', $browserId))->where('protocol', $protocol)->where('expires_at', '>', now());
        $row = (clone $query)->first();
        if (! $row || $query->delete() !== 1) {
            throw new IdentityException('invalid_login_state', 401);
        }

        return $this->vault->open($row->intent, 'intent:'.$id);
    }
}
