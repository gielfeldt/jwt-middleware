<?php

namespace Gielfeldt\JwtMiddleware;

use Psr\Http\Message\ServerRequestInterface;

class HeaderTokenProvider implements TokenProviderInterface
{
    private string $headerName;
    private string $regex;

    public function __construct(string $headerName = 'Authorization', string $regex = '/^Bearer\s+(.*)$/i')
    {
        $this->headerName = $headerName;
        $this->regex = $regex;
    }

    public function getToken(ServerRequestInterface $request): string
    {
        $header = $request->getHeaderLine($this->headerName);

        if (false === empty($header)) {
            if (preg_match($this->regex, $header, $matches)) {
                return $matches[1];
            }
        }
        throw new TokenNotFoundException("Token not found in header: {$this->headerName}");
    }
}
