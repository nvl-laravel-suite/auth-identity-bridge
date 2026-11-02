<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users\Transforms;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Users\NativeValueTransform;

final class NullableDate implements NativeValueTransform
{
    public static function validate(array $options): void
    {
        Contract::require($options === [], 'identity_user_mapping_invalid', 503);
    }

    public function transform(mixed $value, array $options): mixed
    {
        if ($value === null) {
            return null;
        }
        Contract::require(is_string($value) && preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/', $value, $parts) === 1 && checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1]), 'native_transform_invalid', 503);

        return $value;
    }
}
