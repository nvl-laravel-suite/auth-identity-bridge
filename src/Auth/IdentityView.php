<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use JsonSerializable;

final readonly class IdentityView implements JsonSerializable
{
    public function __construct(public string $subject, public ?string $name = null, public ?string $email = null, public ?string $picture = null) {}

    public function jsonSerialize(): array
    {
        return ['subject' => $this->subject, 'name' => $this->name, 'email' => $this->email, 'picture' => $this->picture];
    }
}
