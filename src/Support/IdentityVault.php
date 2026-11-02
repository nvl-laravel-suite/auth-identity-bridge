<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Support\Facades\Crypt;
use Throwable;

class IdentityVault
{
    public function __construct(private IdentityConfig $config) {}

    public function seal(array $payload, string $purpose): string
    {
        return Crypt::encryptString(json_encode(['binding' => $this->config->bindingHash(), 'purpose' => $purpose, 'payload' => $payload], JSON_THROW_ON_ERROR));
    }

    public function open(string $ciphertext, string $purpose): array
    {
        try {
            $data = json_decode(Crypt::decryptString($ciphertext), true, 64, JSON_THROW_ON_ERROR);
            if (! hash_equals($this->config->bindingHash(), $data['binding'] ?? '') || ! hash_equals($purpose, $data['purpose'] ?? '') || ! is_array($data['payload'] ?? null)) {
                throw new IdentityException('vault_binding_failed', 401);
            }

            return $data['payload'];
        } catch (Throwable) {
            throw new IdentityException('vault_binding_failed', 401);
        }
    }
}
