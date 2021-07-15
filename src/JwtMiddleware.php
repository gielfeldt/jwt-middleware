<?php

namespace Gielfeldt\JwtMiddleware;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class JwtMiddleware implements MiddlewareInterface
{
    private ResponseFactoryInterface $responseFactory;
    private Configuration $config;
    private TokenProviderInterface $tokenProvider;

    public function __construct(ResponseFactoryInterface $responseFactory, Configuration $config, ?TokenProviderInterface $tokenProvider = null)
    {
        $this->responseFactory = $responseFactory;
        $this->config = $config;
        $this->tokenProvider = $tokenProvider ?? TokenProviders::withDefaultProviders();
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $rawToken = $this->tokenProvider->getToken($request);
            $token = $this->config->parser()->parse($rawToken);

            $constraints = $this->config->validationConstraints();
            if ($constraints) {
                $this->config->validator()->assert($token, ...$constraints);
            }

            $request = $request->withAttribute('token', $token);

            return $handler->handle($request);
        } catch (RequiredConstraintsViolated | TokenNotFoundException $e) {
            $response = $this->responseFactory->createResponse(401);
            $response->getBody()->write($e->getMessage());
            return $response->withHeader('Content-Type', 'text/plain');
        }
    }
}
