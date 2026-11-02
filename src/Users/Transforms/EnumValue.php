<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users\Transforms;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Users\NativeValueTransform;

final class EnumValue implements NativeValueTransform
{
    public static function validate(array $options): void
    {
        Contract::require(array_keys($options) === ['enum'] && is_string($options['enum']) && enum_exists($options['enum']) && is_subclass_of($options['enum'], \BackedEnum::class), 'identity_user_mapping_invalid', 503);
    }

    public function transform(mixed $value, array $options): mixed
    {
        if ($value === null) {
            return null;
        }
        $class = $options['enum'];
        Contract::require((is_string($value) || is_int($value)) && ($enum = $class::tryFrom($value)) !== null, 'native_transform_invalid', 503);

        return $enum->value;
    }
}
