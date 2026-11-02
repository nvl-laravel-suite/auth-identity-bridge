<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Console;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use Illuminate\Console\Command;

/** Reports configuration readiness without exposing credentials or contacting the provider. */
class DoctorIdentityBridge extends Command
{
    protected $signature = 'nvl:auth-identity-bridge:doctor {--strict} {--format=text}';

    protected $description = 'Check the configured Identity Platform bridge';

    public function handle(): int
    {
        $enabled = config('nvl-auth-identity-bridge.enabled', false) === true;
        $code = 'disabled';
        $valid = true;
        if ($enabled) {
            try {
                app(ConsumerRegistry::class);
                $code = 'configured';
            } catch (IdentityException $error) {
                $code = $error->errorCode;
                $valid = false;
            }
        }
        $format = $this->option('format');
        if (! in_array($format, ['text', 'json'], true)) {
            $this->error('Format must be text or json.');

            return self::INVALID;
        }
        $this->line($format === 'json' ? json_encode(['enabled' => $enabled, 'valid' => $valid, 'code' => $code], JSON_THROW_ON_ERROR) : 'Identity bridge: '.$code);

        return $valid ? self::SUCCESS : self::FAILURE;
    }
}
