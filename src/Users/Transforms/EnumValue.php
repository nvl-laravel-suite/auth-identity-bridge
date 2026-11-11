<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users\Transforms;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Users\NativeValueTransform;

final class EnumValue implements NativeValueTransform
{
    /**
     * @param  array<array-key, mixed>  $options
     *
     * @phpstan-assert array{enum: class-string<\BackedEnum>} $options
     */
    public static function validate(array $options): void
    {
        Contract::require(array_keys($options) === ['enum'] && is_string($options['enum']) && enum_exists($options['enum']) && is_subclass_of($options['enum'], \BackedEnum::class), 'identity_user_mapping_invalid', 503);
    }

    /**
     * @param  array<array-key, mixed>  $options
     */
    public function transform(mixed $value, array $options): mixed
    {
        if ($value === null) {
            return null;
        }
        self::validate($options);
        $class = $options['enum'];
        // tryFrom() raises a TypeError, not a refusal, for a value of the other backing type.
        $integerBacked = (string) (new \ReflectionEnum($class))->getBackingType() === 'int';
        Contract::require($integerBacked ? is_int($value) : is_string($value), 'native_transform_invalid', 503);
        $enum = $class::tryFrom($value);
        Contract::require($enum !== null, 'native_transform_invalid', 503);

        return $enum->value;
    }
}
