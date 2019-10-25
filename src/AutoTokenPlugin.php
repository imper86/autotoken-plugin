<?php
/**
 * Author: Adrian Szuszkiewicz <me@imper.info>
 * Github: https://github.com/imper86
 * Date: 25.10.2019
 * Time: 15:18
 */

namespace Imper86\AutoTokenPlugin;

use Http\Client\Common\Plugin;
use Http\Promise\Promise;
use Imper86\OauthClient\Model\TokenInterface;
use Imper86\OauthClient\OauthClientInterface;
use Imper86\OauthClient\Repository\TokenRepositoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class AutoTokenPlugin implements Plugin
{
    /**
     * @var string
     */
    private $ownerIdentifier;
    /**
     * @var TokenRepositoryInterface
     */
    private $tokenRepository;
    /**
     * @var OauthClientInterface
     */
    private $oauthClient;
    /**
     * @var int
     */
    private $retriesLeft = 3;
    /**
     * @var int
     */
    private $maxRetries;

    public function __construct(
        string $ownerIdentifier,
        TokenRepositoryInterface $tokenRepository,
        OauthClientInterface $oauthClient,
        int $maxRetries = 3
    )
    {
        $this->ownerIdentifier = $ownerIdentifier;
        $this->tokenRepository = $tokenRepository;
        $this->oauthClient = $oauthClient;
        $this->maxRetries = $maxRetries;
        $this->retriesLeft = $maxRetries;
    }

    public function handleRequest(RequestInterface $request, callable $next, callable $first): Promise
    {
        if (!$request->hasHeader('Authorization')) {
            $request = $request->withHeader('Authorization', "Bearer {$this->getActiveToken()}");
        }

        return $next($request)->then(function (ResponseInterface $response) use ($request, $first) {
            if (401 === $response->getStatusCode() && $this->retriesLeft > 0) {
                $this->retriesLeft--;

                $token = $this->tokenRepository->load($this->ownerIdentifier);
                $newToken = $this->oauthClient->refreshToken($token);

                return $first($request->withHeader('Authorization', "Bearer {$newToken}"));
            }

            $this->retriesLeft = $this->maxRetries;

            return $response;
        });
    }

    private function getActiveToken(): TokenInterface
    {
        $token = $this->tokenRepository->load($this->ownerIdentifier);

        if ($token->isExpired()) {
            $token = $this->oauthClient->refreshToken($token);
        }

        return $token;
    }
}
