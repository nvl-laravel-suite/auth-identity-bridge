<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class IdentityPsrClient implements ClientInterface
{
    public function __construct(private IdentityHttp $http) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        return $this->http->sendPsr($request);
    }
}
