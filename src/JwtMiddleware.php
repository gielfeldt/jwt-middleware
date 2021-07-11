<?php

namespace Gielfeldt\JwtMiddleware;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;

class JwtMiddleware implements MiddlewareInterface
{
    private ResponseFactoryInterface $responseFactory;
    private Configuration $config;
    private TokenProviderInterface $tokenProvider;

    public function __construct(ResponseFactoryInterface $responseFactory, Configuration $config, TokenProviderInterface $tokenProvider)
    {
        $this->responseFactory = $responseFactory;
        $this->config = $config;
        $this->tokenProvider = $tokenProvider;
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
        } catch (RequiredConstraintsViolated $e) {
            $message = array_map(function ($v) {
                return $v->getMessage();
            }, $e->violations());
            return $this->responseFactory->createResponse(401, implode(' - ', $message));
        } catch (Throwable $e) {
            return $this->responseFactory->createResponse(401, $e->getMessage());
        }
    }
}
