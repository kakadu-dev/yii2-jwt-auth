<?php
/**
 * Created by PhpStorm.
 * User: mikhail
 * Date: 23.10.2018
 * Time: 12:10
 */

namespace Kakadu\Yii2JwtAuth;

use yii\base\InvalidConfigException;
use yii\db\Exception;
use yii\di\Instance;
use yii\filters\auth\HttpBearerAuth;
use yii\web\Request;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;

/**
 * Class    JwtBearerAuth
 * @package Kakadu\Yii2JwtAuth
 * @author  Yarmaliuk Mikhail
 * @version 1.0
 */
class JwtBearerAuth extends HttpBearerAuth
{
    /**
     * @inheritdoc
     */
    public $pattern = '/^Jwt\s+(.*?)$/';

    /**
     * @var string the HTTP refresh token header name
     */
    public $headerRefresh = 'Authorization-Refresh';

    /**
     * @var string the HTTP new jwt access token header name
     */
    public $jwtHeader = 'Jwt-Access-Token';

    /**
     * @var string the HTTP new jwt refresh token header name
     */
    public $jwtRefreshHeader = 'Jwt-Refresh-Token';

    /**
     * @var ApiTokenService|string token component name or instance
     */
    public $apiTokens = 'apiTokens';

    /**
     * Add api token to header
     *
     * @param Response      $response
     * @param ApiToken|null $apiToken
     * @param array         $params
     *
     * @return void
     */
    public static function addJwtToHeader($response, ApiToken $apiToken = null, array $params = []): void
    {
        if (!$apiToken) {
            return;
        }

        $authInstance = new self();

        $headerAccessTokenName  = $params['accessHeader'] ?? $authInstance->jwtHeader;
        $headerRefreshTokenName = $params['refreshHeader'] ?? $authInstance->jwtRefreshHeader;

        if (!($params['disableAccess'] ?? null)) {
            $response->headers->set($headerAccessTokenName, $apiToken->access_token);
        }

        if (!($params['disableRefresh'] ?? null)) {
            $response->headers->set($headerRefreshTokenName, $apiToken->refresh_token);
        }
    }

    /**
     * @inheritdoc
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        $this->apiTokens = Instance::ensure($this->apiTokens, ApiTokenService::class);
    }

    /**
     * @inheritdoc
     * @throws Exception
     */
    public function authenticate($user, $request, $response)
    {
        $jwtAccessToken = $this->getJwtAuthToken($request);

        if ($jwtAccessToken === null) {
            return null;
        }

        if ($jwtAccessToken->isInvalid()) {
            $this->failure($response);
        }

        if ($jwtAccessToken->isExpired()) {
            if (!$this->apiTokens->seamlessLogin) {
                $this->failure($response);
            }

            if (!$this->renewToken($request, $response)) {
                $this->failure($response);
            }
        }

        return parent::authenticate($user, $request, $response);
    }

    /**
     * Get jwt auth token from headers
     *
     * @param Request $request
     *
     * @return JwtToken|null
     */
    protected function getJwtAuthToken($request): ?JwtToken
    {
        $token = $this->getAuthHeader($request);

        if ($token === null) {
            return null;
        }

        return $this->apiTokens->getJwtToken($token);
    }

    /**
     * Get header
     *
     * @param Request $request
     *
     * @return null|string
     */
    protected function getAuthHeader($request): ?string
    {
        $authHeader = $request->headers->get($this->header);

        if ($authHeader !== null && $this->pattern !== null) {
            if (preg_match($this->pattern, $authHeader, $matches)) {
                $authHeader = $matches[1];
            } else {
                return null;
            }
        }

        return $authHeader;
    }

    /**
     * Failure jwt
     *
     * @param Response $response
     *
     * @throws UnauthorizedHttpException
     */
    protected function failure($response): void
    {
        $this->challenge($response);
        $this->handleFailure($response);
    }

    /**
     * Force renew existed token.
     *
     * @param Request $request
     * @param Response $response
     *
     * @return bool
     * @throws Exception
     */
    public function renewToken(Request $request, Response $response): bool
    {
        $jwtAccessToken = $this->getJwtAuthToken($request);

        if ($jwtAccessToken === null || $jwtAccessToken->isInvalid()) {
            return false;
        }

        // Seamless login
        $jwtRefresh = $this->getJwtRefreshHeaderToken($request);

        if ($jwtRefresh === null) {
            return false;
        }

        $newApiToken = $this->apiTokens->renewJwtToken($jwtAccessToken, $jwtRefresh);

        if (!$newApiToken) {
            return false;
        }

        // Add new access and refresh token to response headers
        $response->headers->set($this->jwtHeader, $newApiToken->access_token);
        $response->headers->set($this->jwtRefreshHeader, $newApiToken->refresh_token);

        $authHeader   = $request->headers->get($this->header);
        $expiredToken = $this->getAuthHeader($request);

        // Change expired access token to new
        $request->headers->set($this->header, str_replace($expiredToken, $newApiToken->access_token, $authHeader));

        return true;
    }

    /**
     * Get jwt refresh token from headers
     *
     * @param Request $request
     *
     * @return JwtToken|null
     */
    protected function getJwtRefreshHeaderToken($request): ?JwtToken
    {
        $token = $request->headers->get($this->headerRefresh);
        if ($token === null) {
            return null;
        }

        return $this->apiTokens->getJwtToken($token);
    }
}