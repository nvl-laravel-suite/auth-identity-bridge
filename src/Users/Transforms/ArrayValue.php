<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users\Transforms;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Users\NativeValueTransform;

final class ArrayValue implements NativeValueTransform
{
    /**
     * @param  array<array-key, mixed>  $options
     */
    public static function validate(array $options): void
    {
        Contract::require($options === [], 'identity_user_mapping_invalid', 503);
    }

    /**
     * @param  array<array-key, mixed>  $options
     */
    public function transform(mixed $value, array $options): mixed
    {
        Contract::require($value === null || is_array($value), 'native_transform_invalid', 503);

        return $value;
    }
}
