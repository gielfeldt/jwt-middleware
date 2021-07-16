<?php

namespace Gielfeldt\JwtMiddleware;

use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

class TokenProviders implements TokenProviderInterface
{
    private array $providers = [];

    public function addProvider(TokenProviderInterface $provider)
    {
        $this->providers[] = $provider;
    }

    public function getToken(ServerRequestInterface $request): string
    {
        if (empty($this->providers)) {
            throw new NoTokenProvidersException("No token providers defined");
        }
        $errors = [];
        foreach ($this->providers as $provider) {
            try {
                return $provider->getToken($request);
            } catch (TokenNotFoundException $e) {
                // save error, try next provider
                $errors[] = '- ' . get_class($provider) . ': ' . $e->getMessage();
            }
        }
        $message = "Token not found by any provider\n";
        $message .= join("\n", $errors);
        throw new TokenNotFoundException($message);
    }

    public static function withDefaultProviders(): TokenProviderInterface
    {
        $provider = new self();
        $provider->addProvider(new HeaderTokenProvider());
        $provider->addProvider(new CookieTokenProvider());
        return $provider;
    }
}
