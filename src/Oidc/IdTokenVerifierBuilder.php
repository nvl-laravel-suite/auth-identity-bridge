<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Oidc;

use Facile\OpenIDClient\Client\ClientInterface;
use Facile\OpenIDClient\Token\IdTokenVerifierBuilder as FacileIdTokenVerifierBuilder;
use Facile\OpenIDClient\Token\IdTokenVerifierBuilderInterface;

/** Keep Facile's JOSE checks and supply the configured OIDC hash profile. */
final class IdTokenVerifierBuilder implements IdTokenVerifierBuilderInterface
{
    public function build(ClientInterface $client): IdTokenVerifier
    {
        return new IdTokenVerifier(
            (new FacileIdTokenVerifierBuilder)->build($client),
            $client->getMetadata()->getIdTokenSignedResponseAlg(),
        );
    }
}
