<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use JsonSerializable;

/** @phpstan-type IdentityFacts array{subject: string, name: string|null, email: string|null, picture: string|null} */
final readonly class IdentityView implements JsonSerializable
{
    public function __construct(public string $subject, public ?string $name = null, public ?string $email = null, public ?string $picture = null) {}

    /**
     * @return IdentityFacts
     */
    public function jsonSerialize(): array
    {
        return ['subject' => $this->subject, 'name' => $this->name, 'email' => $this->email, 'picture' => $this->picture];
    }
}
