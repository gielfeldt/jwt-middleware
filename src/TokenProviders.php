<?php

namespace Gielfeldt\JwtMiddleware;

use Psr\Http\Message\ServerRequestInterface;

class TokenProviders implements TokenProviderInterface
{
    private array $providers = [];

    public function addProvider(TokenProviderInterface $provider)
    {
        $this->providers[] = $provider;
    }

    public function getToken(ServerRequestInterface $request): string
    {
        foreach ($this->providers as $provider) {
            try {
                return $provider->getToken($request);
            } catch (TokenNotFoundException $e) {
                // black hole, try next provider
            }
        }
        throw new TokenNotFoundException("Token not found by any provider. " . count($this->providers) . ' tried');
    }

    public static function withDefaultProviders(): TokenProviderInterface
    {
        $provider = new self();
        $provider->addProvider(new HeaderTokenProvider());
        $provider->addProvider(new CookieTokenProvider());
        return $provider;
    }
}
