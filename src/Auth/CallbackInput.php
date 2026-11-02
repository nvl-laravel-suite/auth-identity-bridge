<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Http\Request;

/** Validate raw evidence before PHP's query parser can hide duplicate or array fields. */
final class CallbackInput
{
    /**
     * @param  array<array-key, mixed>  $callback
     * @return array<array-key, string>
     */
    public static function validate(Request $request, array $callback): array
    {
        $query = $request->server('QUERY_STRING', '');
        if (! is_string($query) || strlen($query) > 16384) {
            throw new IdentityException('callback_invalid', 400);
        }
        $seen = [];
        foreach (explode('&', $query) as $field) {
            $key = urldecode(explode('=', $field, 2)[0]);
            if (preg_match('/\A(state|code|iss|error|error_description|error_uri|session_state)(.*)\z/', $key, $match) && ($match[2] === '' || str_starts_with($match[2], '['))) {
                if ($match[2] !== '' || isset($seen[$key])) {
                    throw new IdentityException('callback_invalid', 400);
                }
                $seen[$key] = true;
            }
        }
        foreach ($callback as $value) {
            if (! is_string($value) || strlen($value) > 8192) {
                throw new IdentityException('callback_invalid', 400);
            }
        }

        return $callback;
    }
}
