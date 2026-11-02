<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Controllers;

use IdentityPlatform\Laravel\Callbacks\CallbackReceiver;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Throwable;

class CallbackController
{
    public function __construct(private CallbackReceiver $callbacks) {}

    public function event(Request $request): JsonResponse
    {
        return $this->run(function () use ($request) {
            if ($this->mediaType($request) !== 'application/json') {
                throw new IdentityException('invalid_content_type', 415);
            }

            return $this->callbacks->event($request->getContent(), $request->headers->all());
        });
    }

    public function logout(Request $request): JsonResponse
    {
        return $this->run(function () use ($request) {
            if ($this->mediaType($request) !== 'application/x-www-form-urlencoded') {
                throw new IdentityException('invalid_content_type', 415);
            }

            return $this->callbacks->logout($request->getContent());
        });
    }

    /**
     * @param  callable(): array{duplicate: bool, affected: int}  $work
     */
    private function run(callable $work): JsonResponse
    {
        try {
            $response = response()->json($work());
        } catch (IdentityException $error) {
            $response = response()->json(['error' => $error->errorCode], $error->status);
        } catch (Throwable) {
            // Database and infrastructure messages can contain sensitive request facts.
            $response = response()->json(['error' => 'callback_unavailable'], 503);
        }

        return $response->header('Cache-Control', 'no-store')->header('X-Content-Type-Options', 'nosniff');
    }

    private function mediaType(Request $request): string
    {
        return strtolower(trim(explode(';', $request->header('Content-Type', ''))[0]));
    }
}
