<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

interface NativeValueTransform
{
    /**
     * @param  array<array-key, mixed>  $options
     */
    public static function validate(array $options): void;

    /**
     * @param  array<array-key, mixed>  $options
     */
    public function transform(mixed $value, array $options): mixed;
}
