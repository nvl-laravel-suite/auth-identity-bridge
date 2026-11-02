<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Callbacks;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;

final class CallbackReceiver
{
    public function __construct(private IdentityConfig $config, private IdentityHttp $http, private CallbackRepository $repository) {}

    public function event(string $rawBody, array $headers): array
    {
        $this->bounded($rawBody);
        $event = (new IdentityEventVerifier($this->config))->verify($rawBody, $headers);

        return $this->repository->event($event, hash('sha256', $rawBody));
    }

    public function logout(string $rawBody): array
    {
        $this->bounded($rawBody);
        if (! mb_check_encoding($rawBody, 'UTF-8')) {
            throw new IdentityException('logout_token_invalid', 400);
        }
        $fields = explode('&', $rawBody);
        if (count($fields) !== 1) {
            throw new IdentityException('logout_token_invalid', 400);
        }
        [$key, $value] = array_pad(explode('=', $fields[0], 2), 2, '');
        $token = urldecode($value);
        if (urldecode($key) !== 'logout_token' || $token === '') {
            throw new IdentityException('logout_token_invalid', 400);
        }
        $claims = (new LogoutTokenVerifier($this->config, $this->http))->verify($token);

        return $this->repository->logout($claims, hash('sha256', $token));
    }

    private function bounded(string $body): void
    {
        if ($body === '') {
            throw new IdentityException('callback_body_required', 400);
        }
        if (strlen($body) > 65536) {
            throw new IdentityException('callback_body_limit', 413);
        }
    }
}
