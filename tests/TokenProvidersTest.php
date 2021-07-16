<?php

namespace Gielfeldt\JwtMiddleware\Tests;

use Gielfeldt\JwtMiddleware\NoTokenProvidersException;
use Gielfeldt\JwtMiddleware\TokenNotFoundException;
use Gielfeldt\JwtMiddleware\TokenProviders;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

class TokenProvidersTest extends TestCase
{
    public function testCanRetrieveTokenFromMultipleProviders()
    {
        $factory = new Psr17Factory();
        $providers = TokenProviders::withDefaultProviders();

        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withHeader('Authorization', 'Bearer my-token');
        $token = $providers->getToken($request);
        $this->assertEquals('my-token', $token);

        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withCookieParams(['jwt' => 'my-token']);
        $token = $providers->getToken($request);
        $this->assertEquals('my-token', $token);
    }

    public function testWillFailOnMissingToken()
    {
        $factory = new Psr17Factory();
        $providers = TokenProviders::withDefaultProviders();

        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withHeader('Not-Authorization', 'Bearer my-token');
        $request = $request->withCookieParams(['not-jwt' => 'my-token']);
        $this->expectException(TokenNotFoundException::class);
        $providers->getToken($request);
    }

    public function testWillFailOnMissingTokenProviders()
    {
        $factory = new Psr17Factory();
        $providers = new TokenProviders();

        $request = $factory->createServerRequest('GET', '/test');
        $this->expectException(NoTokenProvidersException::class);
        $providers->getToken($request);
    }
}
