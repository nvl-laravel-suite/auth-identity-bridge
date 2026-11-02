<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

interface NativeValueTransform
{
    public static function validate(array $options): void;

    public function transform(mixed $value, array $options): mixed;
}
