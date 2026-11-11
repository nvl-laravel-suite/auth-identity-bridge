<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Tests\Support\IntegerTierFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\Transforms\EnumValue;

final class EnumValueTransformTest extends TestCase
{
    public function test_a_value_of_the_wrong_backing_type_is_a_transform_refusal_not_a_type_error(): void
    {
        $transform = new EnumValue;
        $options = ['enum' => IntegerTierFixture::class];

        self::assertSame(2, $transform->transform(2, $options));
        self::assertNull($transform->transform(null, $options));
        foreach (['individual', '2', 3] as $value) {
            try {
                $transform->transform($value, $options);
                self::fail('A value outside the enum was mapped');
            } catch (IdentityException $error) {
                self::assertSame('native_transform_invalid', $error->errorCode);
            }
        }
    }
}
