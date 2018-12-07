<?php
/**
 * Created by PhpStorm.
 * User: mikhail
 * Date: 09.11.2018
 * Time: 11:53
 */

namespace Kakadu\Yii2JwtAuth;

use yii\base\Action;
use yii\di\Instance;
use yii\web\Request;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;

/**
 * Class    RefreshTokensAction
 * @package Kakadu\Yii2JwtAuth
 * @author  Yarmaliuk Mikhail
 * @version 1.0
 */
class RefreshTokensAction extends Action
{
    /**
     * @var ApiTokenService|string token component name or instance
     */
    public $apiTokens = 'apiTokens';

    /**
     * @var Response|string response component name or instance
     */
    public $response = 'response';

    /**
     * @var Request|string request component name or instance
     */
    public $request = 'request';

    /**
     * @var string the HTTP refresh token header name
     */
    public $headerRefresh = 'Authorization-Refresh';

    /**
     * @var string the HTTP access token header name
     */
    public $accessToken = 'Authorization';

    /**
     * @inheritdoc
     */
    public $pattern = '/^Jwt\s+(.*?)$/';

    /**
     * @inheritdoc
     * @throws \yii\base\InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        $this->apiTokens = Instance::ensure($this->apiTokens, ApiTokenService::class);
        $this->response  = Instance::ensure($this->response, Response::class);
        $this->request   = Instance::ensure($this->request, Request::class);
    }

    /**
     * Renew tokens
     *
     * @return void
     * @throws UnauthorizedHttpException
     */
    public function run(): void
    {
        ['accessToken' => $accessToken, 'refreshToken' => $refreshToken] = $this->getTokens();
        if ($accessToken === null || $refreshToken === null) {
            // TODO: set correct message.
            throw new UnauthorizedHttpException(\Yii::t('app', 'Your request was made with invalid credentials.'));
        }

        // Convert to jwt token model
        $accessToken  = $this->apiTokens->getJwtToken($accessToken);
        $refreshToken = $this->apiTokens->getJwtToken($refreshToken);
        if ($accessToken === null || $refreshToken === null) {
            // TODO: set correct message.
            throw new UnauthorizedHttpException(\Yii::t('app', 'Your request was made with invalid credentials.'));
        }

        // Renew
        $newTokens = $this->apiTokens->renewJwtToken($accessToken, $refreshToken);

        if (!$newTokens) {
            // TODO: set correct message.
            throw new UnauthorizedHttpException(\Yii::t('app', 'Your request was made with invalid credentials.'));
        }

        JwtBearerAuth::addJwtToHeader($this->response, $newTokens);
    }

    /**
     * Get tokens from headers
     *
     * @return array
     */
    protected function getTokens(): array
    {
        return [
            'accessToken'  => $this->getTokenString($this->request->headers->get($this->accessToken)),
            'refreshToken' => $this->request->headers->get($this->headerRefresh),
        ];
    }

    /**
     * Get jwt token string
     *
     * @param string $authHeader
     *
     * @return null|string
     */
    protected function getTokenString(?string $authHeader): ?string
    {
        if ($authHeader === '') {
            return null;
        }

        if ($this->pattern === null) {
            return $authHeader;
        }

        if (!preg_match($this->pattern, $authHeader, $matches)) {
            return null;
        }

        return $matches[1] ?? null;
    }
}