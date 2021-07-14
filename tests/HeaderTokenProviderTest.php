<?php

namespace Gielfeldt\JwtMiddleware\Tests;

use Gielfeldt\JwtMiddleware\HeaderTokenProvider;
use Gielfeldt\JwtMiddleware\TokenNotFoundException;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

class HeaderTokenProviderTest extends TestCase
{
    public function testCanRetrieveTokenFromHeader()
    {
        $factory = new Psr17Factory();
        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withHeader('Authorization', 'Bearer my-token');

        $provider = new HeaderTokenProvider();

        $token = $provider->getToken($request);

        $this->assertEquals('my-token', $token);
    }

    public function testWillFailOnMissingHeader()
    {
        $factory = new Psr17Factory();
        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withHeader('Not-Authorization', 'Bearer my-token');

        $provider = new HeaderTokenProvider();

        $this->expectException(TokenNotFoundException::class);
        $provider->getToken($request);
    }
}
