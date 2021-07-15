<?php

namespace Gielfeldt\JwtMiddleware;

use Psr\Http\Message\ServerRequestInterface;

class CookieTokenProvider implements TokenProviderInterface
{
    private string $cookieName;

    public function __construct(string $cookieName = 'jwt')
    {
        $this->cookieName = $cookieName;
    }

    public function getToken(ServerRequestInterface $request): string
    {
        $cookies = $request->getCookieParams();
        $token = $cookies[$this->cookieName] ?? null;
        if (!$token) {
            throw new TokenNotFoundException("Token not found in header: {$this->cookieName}");
        }
        return $token;
    }
}
