<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users\Transforms;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Support\AvatarUrl;
use IdentityPlatform\Laravel\Users\NativeValueTransform;

final class SafeAvatar implements NativeValueTransform
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
        return AvatarUrl::safe($value);
    }
}
