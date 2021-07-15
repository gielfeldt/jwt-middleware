<?php

namespace Gielfeldt\JwtMiddleware\Tests;

use Gielfeldt\JwtMiddleware\CookieTokenProvider;
use Gielfeldt\JwtMiddleware\HeaderTokenProvider;
use Gielfeldt\JwtMiddleware\TokenNotFoundException;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

class CookieTokenProviderTest extends TestCase
{
    public function testCanRetrieveTokenFromCookie()
    {
        $factory = new Psr17Factory();
        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withCookieParams([
            'jwt' => 'my-token'
        ]);

        $provider = new CookieTokenProvider();

        $token = $provider->getToken($request);

        $this->assertEquals('my-token', $token);
    }

    public function testWillFailOnMissingHeader()
    {
        $factory = new Psr17Factory();
        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withCookieParams([
            'not-jwt' => 'my-token'
        ]);

        $provider = new CookieTokenProvider();

        $this->expectException(TokenNotFoundException::class);
        $provider->getToken($request);
    }
}
