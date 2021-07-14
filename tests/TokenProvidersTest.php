<?php

namespace Gielfeldt\JwtMiddleware\Tests;

use Gielfeldt\JwtMiddleware\HeaderTokenProvider;
use Gielfeldt\JwtMiddleware\TokenNotFoundException;
use Gielfeldt\JwtMiddleware\TokenProviders;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

class TokenProvidersTest extends TestCase
{
    public function testCanRetrieveTokenFromMultipleProviders()
    {
        $factory = new Psr17Factory();
        $providers = new TokenProviders();
        $providers->addProvider(new HeaderTokenProvider('test1'));
        $providers->addProvider(new HeaderTokenProvider('test2'));

        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withHeader('test1', 'Bearer my-token');
        $token = $providers->getToken($request);
        $this->assertEquals('my-token', $token);

        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withHeader('test2', 'Bearer my-token');
        $token = $providers->getToken($request);
        $this->assertEquals('my-token', $token);
    }

    public function testWillFailOnMissingToken()
    {
        $factory = new Psr17Factory();
        $providers = new TokenProviders();
        $providers->addProvider(new HeaderTokenProvider('test1'));
        $providers->addProvider(new HeaderTokenProvider('test2'));

        $request = $factory->createServerRequest('GET', '/test');
        $request = $request->withHeader('test3', 'Bearer my-token');
        $this->expectException(TokenNotFoundException::class);
        $providers->getToken($request);
    }
}
