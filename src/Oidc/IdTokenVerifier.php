<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Oidc;

use Facile\JoseVerifier\IdTokenVerifierInterface;
use Facile\JoseVerifier\TokenVerifierInterface;
use IdentityPlatform\Laravel\Exceptions\IdentityException;

/**
 * Facile validates signature, pinned algorithm, issuer, audience, time and nonce.
 * Its suffix-based hash selector treats EdDSA as SHA-256; this adapter checks
 * OIDC hashes with the trusted configured profile, including Ed25519 SHA-512.
 */
final class IdTokenVerifier implements IdTokenVerifierInterface
{
    /** @var array<string, string|null> */
    private array $hashInputs = [];

    private TokenVerifierInterface $verifier;

    public function __construct(IdTokenVerifierInterface $verifier, private readonly string $algorithm)
    {
        $this->verifier = $verifier;
    }

    public function withAccessToken(#[\SensitiveParameter] ?string $accessToken): static
    {
        return $this->withHashInput('at_hash', $accessToken);
    }

    public function withCode(#[\SensitiveParameter] ?string $code): static
    {
        return $this->withHashInput('c_hash', $code);
    }

    public function withState(?string $state): static
    {
        return $this->withHashInput('s_hash', $state);
    }

    public function withNonce(?string $nonce): static
    {
        $copy = clone $this;
        $copy->verifier = $this->verifier->withNonce($nonce);

        return $copy;
    }

    public function withMaxAge(?int $maxAge): static
    {
        $copy = clone $this;
        $copy->verifier = $this->verifier->withMaxAge($maxAge);

        return $copy;
    }

    /** @return array<string, mixed> */
    public function verify(#[\SensitiveParameter] string $jwt): array
    {
        // A foreign algorithm is a forged token, not a provider outage; refuse it before any key is selected.
        $header = json_decode((string) base64_decode(strtr(explode('.', $jwt)[0], '-_', '+/'), true), true);
        if (! is_array($header) || ($header['alg'] ?? null) !== $this->algorithm) {
            throw new IdentityException('oidc_token_invalid', 401);
        }
        $claims = $this->verifier->verify($jwt);
        $hashAlgorithm = match ($this->algorithm) {
            'EdDSA' => 'sha512',
            'ES256', 'RS256' => 'sha256',
            default => throw new IdentityException('oidc_algorithm_unavailable', 503),
        };
        foreach ($this->hashInputs as $claim => $input) {
            if ($input === null || ! array_key_exists($claim, $claims)) {
                continue;
            }
            $digest = hash($hashAlgorithm, $input, true);
            $expected = rtrim(strtr(base64_encode(substr($digest, 0, intdiv(strlen($digest), 2))), '+/', '-_'), '=');
            if (! is_string($claims[$claim]) || ! hash_equals($expected, $claims[$claim])) {
                throw new IdentityException('oidc_token_hash_invalid', 401);
            }
        }

        return $claims;
    }

    private function withHashInput(string $claim, #[\SensitiveParameter] ?string $value): static
    {
        $copy = clone $this;
        $copy->hashInputs[$claim] = $value;

        return $copy;
    }
}
