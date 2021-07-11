<?php

namespace Gielfeldt\JwtMiddleware\Tests;

use DateTimeImmutable;
use DateTimeZone;
use Gielfeldt\JwtMiddleware\HeaderTokenProvider;
use Gielfeldt\JwtMiddleware\JwtMiddleware;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class JwtMiddlewareTest extends TestCase implements RequestHandlerInterface
{
    private Psr17Factory $factory;

    public function setUp(): void
    {
        parent::setup();
        $this->factory = new Psr17Factory();
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        #var_dump($request->getAttribute('token'));
        $token = $request->getAttribute('token');
        $phrase = $token ? $token->headers()->get('kid', 'NOK') : 'OK';
        return $this->factory->createResponse(200, $phrase);
    }

    public function testCanHandleMissingToken()
    {
        $config = Configuration::forUnsecuredSigner();
        $provider = new HeaderTokenProvider();
        $middleware = new JwtMiddleware($this->factory, $config, $provider);
        $request = $this->factory->createServerRequest('GET', '/');
        $response = $middleware->process($request, $this);
        $this->assertEquals('Token not found in header', $response->getReasonPhrase());
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testCanHandleInvalidToken()
    {
        $config = Configuration::forUnsecuredSigner();
        $provider = new HeaderTokenProvider();
        $middleware = new JwtMiddleware($this->factory, $config, $provider);
        $request = $this->factory->createServerRequest('GET', '/')
            ->withHeader('Authorization', 'Bearer not-a-valid-token');
        $response = $middleware->process($request, $this);
        $this->assertEquals('The JWT string must have two dots', $response->getReasonPhrase());
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testCanHandleInvalidBase64Token()
    {
        $config = Configuration::forUnsecuredSigner();
        $provider = new HeaderTokenProvider();
        $middleware = new JwtMiddleware($this->factory, $config, $provider);
        $request = $this->factory->createServerRequest('GET', '/')
            ->withHeader('Authorization', 'Bearer not.a.valid-token');
        $response = $middleware->process($request, $this);
        $this->assertEquals('Error while decoding from Base64Url, invalid base64 characters detected', $response->getReasonPhrase());
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testCanHandleTokenWithExpirationConstracts()
    {
        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRva2VuMSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTYyNjAwNDgwMCwibmJmIjoxNjI2MDA0ODAwLCJleHAiOjE2MjYwMDg0MDB9.gZRO7hQAANDGy9z1hrv9GUkKJMwkz-NhCZMaSWJqB48QrOvrm1kaVbTSRkDyW_d7nngbm-WVAPx6_Zi8JYg-ICExK4KBefj2ZBrUOx_nqvxR_ZGdLVf_ae2FSM0ziP097LxKXA-sgsOHa4V5AC-EGoFni6DoFeeBt2g5_4x5DFHVZuryNQmoCtY_1_ESzIt6XkE-au5mMcijiitUHQ04OO64K_vv0yi_yvPVZxIdn7iAmYxoVL3ByaU3WGA_wF2TZ2MMXCcPhakjoWMRScQ9bLZqnq_WnpIRC4gNiYASt7BLfSs7e9PCKA87mdsf8Y43Acj5KeWhBq8mWPSFY4Ffhg';
        $config = Configuration::forUnsecuredSigner();
        $config->setValidationConstraints(new StrictValidAt(new FrozenClock(new DateTimeImmutable('2021-07-11T12:00:00Z'))));
        $provider = new HeaderTokenProvider();
        $middleware = new JwtMiddleware($this->factory, $config, $provider);
        $request = $this->factory->createServerRequest('GET', '/')
            ->withHeader('Authorization', "Bearer $token");
        $response = $middleware->process($request, $this);
        $this->assertEquals('token1', $response->getReasonPhrase());
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testCanHandleExpiredToken()
    {
        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRva2VuMSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTYyNjAwNDgwMCwibmJmIjoxNjI2MDA0ODAwLCJleHAiOjE2MjYwMDg0MDB9.gZRO7hQAANDGy9z1hrv9GUkKJMwkz-NhCZMaSWJqB48QrOvrm1kaVbTSRkDyW_d7nngbm-WVAPx6_Zi8JYg-ICExK4KBefj2ZBrUOx_nqvxR_ZGdLVf_ae2FSM0ziP097LxKXA-sgsOHa4V5AC-EGoFni6DoFeeBt2g5_4x5DFHVZuryNQmoCtY_1_ESzIt6XkE-au5mMcijiitUHQ04OO64K_vv0yi_yvPVZxIdn7iAmYxoVL3ByaU3WGA_wF2TZ2MMXCcPhakjoWMRScQ9bLZqnq_WnpIRC4gNiYASt7BLfSs7e9PCKA87mdsf8Y43Acj5KeWhBq8mWPSFY4Ffhg';
        $config = Configuration::forUnsecuredSigner();
        $config->setValidationConstraints(new StrictValidAt(new FrozenClock(new DateTimeImmutable('2021-07-11T14:00:00Z'))));
        $provider = new HeaderTokenProvider();
        $middleware = new JwtMiddleware($this->factory, $config, $provider);
        $request = $this->factory->createServerRequest('GET', '/')
            ->withHeader('Authorization', "Bearer $token");
        $response = $middleware->process($request, $this);
        $this->assertEquals('The token is expired', $response->getReasonPhrase());
        $this->assertEquals(401, $response->getStatusCode());
    }
}
