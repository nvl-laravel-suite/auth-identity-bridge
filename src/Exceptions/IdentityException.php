<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Exceptions;

use Illuminate\Contracts\Debug\ShouldntReport;
use RuntimeException;

class IdentityException extends RuntimeException implements ShouldntReport
{
    public function __construct(public readonly string $errorCode, public readonly int $status = 503, public readonly ?int $retryAfter = null)
    {
        parent::__construct('Identity service: '.$errorCode);
    }
}
