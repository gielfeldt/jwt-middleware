<?php

namespace Gielfeldt\JwtMiddleware;

use Psr\Http\Message\ServerRequestInterface;

interface TokenProviderInterface
{
    public function getToken(ServerRequestInterface $request): string;
}
