<?php
/**
 * Created by PhpStorm.
 * User: mikhail
 * Date: 23.10.2018
 * Time: 16:52
 */

namespace Kakadu\Yii2JwtAuth;

use Firebase\JWT\ExpiredException;
use yii\base\Component;
use \Firebase\JWT\JWT;
use yii\helpers\ArrayHelper;

/**
 * Class    ApiTokenService
 * @package Kakadu\Yii2JwtAuth
 * @author  Yarmaliuk Mikhail
 * @version 1.0
 */
class ApiTokenService extends Component
{
    /**
     * @var string
     */
    public $secretKey;

    /**
     * @var string
     */
    public $issuer;

    /**
     * Access token lifetime
     * Default: 2 hours
     *
     * @var int in sec
     */
    public $expiration = 60 * 60 * 2;

    /**
     * Refresh token lifetime
     * Default: 15 day
     *
     * @var int
     */
    public $expirationRefresh = 60 * 60 * 24 * 15;

    /**
     * Set false, to disable
     *
     * @var string|array|null
     */
    public $audience = null;

    /**
     * Allow validate jwt token other issuer
     *
     * 'issuer' => 'secret key'
     *
     * @var array
     */
    public $audienceSecrets = [];

    /**
     * @see JWT::$supported_algs
     *
     * @var string
     */
    public $alg = 'HS256';

    /**
     * Enable/Disable seamless login
     *
     * @var bool
     */
    public $seamless_login = true;

    /**
     * Auto delete expired token
     *
     * @var bool
     */
    public $delete_expired = true;

    /**
     * Create api token
     *
     * @param int   $user_id
     * @param array $params
     *
     * @return ApiToken|null
     */
    public function create(int $user_id, array $params = []): ?ApiToken
    {
        $issuer   = $this->getIssuer();
        $audience = $this->getAudience();

        $accessExpires  = 0;
        $refreshExpires = 0;

        $jwtAccessParams = [
            'user_id' => $user_id,
        ];

        if ($issuer) {
            $jwtAccessParams['iss'] = $issuer;
        }

        if ($audience) {
            $jwtAccessParams['aud'] = $audience;
        }

        if ($this->expiration) {
            $accessExpires          = time() + $this->expiration;
            $jwtAccessParams['exp'] = $accessExpires;
        }

        $jwtRefreshParams = [
            'user_id'      => $user_id,
            'refreshToken' => true,
        ];

        if ($this->expirationRefresh) {
            $refreshExpires          = time() + $this->expirationRefresh;
            $jwtRefreshParams['exp'] = $refreshExpires;
        }

        $accessToken = ArrayHelper::merge($params, $jwtAccessParams);

        $newToken = new ApiToken([
            'user_id'         => $user_id,
            'access_token'    => JWT::encode($accessToken, $this->secretKey, $this->alg),
            'refresh_token'   => JWT::encode($jwtRefreshParams, $this->secretKey, $this->alg),
            'access_expires'  => $accessExpires,
            'refresh_expires' => $refreshExpires,
        ]);

        if ($newToken->save()) {
            return $newToken;
        }

        return null;
    }

    /**
     * Get jwt issuer
     *
     * @return string|null
     */
    private function getIssuer(): ?string
    {
        $inParams = explode('yii-params.', $this->issuer);

        if (!empty($inParams[1])) {
            return \Yii::$app->params[$inParams[1]] ?? $this->issuer;
        }

        return $this->issuer;
    }

    /**
     * Get audience
     *
     * @return array|string|bool
     */
    private function getAudience()
    {
        $audience = $this->audience ?? $this->getIssuer();

        if (is_array($audience)) {
            foreach ($audience as &$item) {
                $inParams = explode('yii-params.', $item);

                if (!empty($inParams[1])) {
                    $item = \Yii::$app->params[$inParams[1]] ?? $item;
                }
            }
        }

        return $audience;
    }

    /**
     * Get audience secrets
     *
     * @return array
     */
    private function getAudienceSecrets(): array
    {
        $audienceSecrets = $this->audienceSecrets;

        foreach ($audienceSecrets as $item => $value) {
            $inParams = explode('yii-params.', $item);

            if (!empty($inParams[1])) {
                $audienceSecrets[\Yii::$app->params[$inParams[1]] ?? $item] = $value;
            }
        }

        return $audienceSecrets;
    }

    /**
     * Get jwt token from string
     *
     * @param string|null $jwtToken
     *
     * @return JwtToken
     */
    public function getJwtToken(string $jwtToken = null): JwtToken
    {
        $jwtModel = new JwtToken();
        $jwtModel->setJwtToken($jwtToken);

        try {
            $jwtModel->setJwtDecodedToken($this->decodeJwt($jwtToken));
        } catch (ExpiredException $expiredException) {
            $jwtModel->setIsExpired(true);
            $jwtModel->setJwtDecodedToken($this->getJwtPayload($jwtToken, false));
        } catch (\Exception $exception) {
            $jwtModel->setIsInvalid(true);
            $jwtModel->setJwtDecodedToken($this->getJwtPayload($jwtToken, false));
        }

        return $jwtModel;
    }

    /**
     * Renew jwt token
     *
     * @param JwtToken $accessToken
     * @param JwtToken $refreshToken
     *
     * @return ApiToken|null
     */
    public function renewJwtToken(JwtToken $accessToken, JwtToken $refreshToken): ?ApiToken
    {
        $oldToken = $this->getApiToken($accessToken->getJwtToken());

        if (!$oldToken || $oldToken->refresh_token !== $refreshToken->getJwtToken()) {
            return null;
        }

        $this->deleteToken($refreshToken->getJwtToken());

        if ($accessToken->isInvalid() || $refreshToken->isInvalid() || $refreshToken->isExpired()) {
            return null;
        }

        $userID = $accessToken->getUserID();
        $params = $accessToken->getJwtDecodedToken();

        $apiToken = $this->create($userID, $params);

        return $apiToken;
    }

    /**
     * Get api token
     *
     * @param string $accessToken
     *
     * @return ApiToken|null
     */
    public function getApiToken(string $accessToken): ?ApiToken
    {
        return ApiToken::findOne([
            'AND',
            ['access_token' => $accessToken],
            [
                'OR',
                ['>', 'access_expires', time()],
                ['=', 'access_expires', 0],
            ],
        ]);
    }

    /**
     * Decode jwt token
     *
     * @param string|null $jwtToken
     *
     * @return array
     */
    private function decodeJwt(string $jwtToken = null): array
    {
        if (!$jwtToken) {
            throw new \UnexpectedValueException('Empty jwt');
        }

        $secretKey = $this->secretKey;

        // Check audience
        if ($this->getAudience() !== false) {
            $payload = $this->getJwtPayload($jwtToken);

            $issuer   = $this->getIssuer();
            $allowAud = $payload['aud'] ?? null;

            if (
                (is_string($allowAud) && $allowAud !== $issuer) ||
                (is_array($allowAud) && !in_array($issuer, $allowAud))
            ) {
                throw new \UnexpectedValueException('Invalid issuer');
            }

            $audSecrets = $this->getAudienceSecrets();

            // Use issuer secret key
            if ($issSecretKey = $audSecrets[$payload['iss'] ?? null] ?? null) {
                $secretKey = $issSecretKey;
            }
        }

        return (array) JWT::decode($jwtToken, $secretKey, [$this->alg]);
    }

    /**
     * Get payload jwt
     *
     * @param string|null $token
     * @param bool        $throwErrors
     *
     * @return array
     */
    private function getJwtPayload(string $token = null, bool $throwErrors = true): array
    {
        $tks = explode('.', $token);

        if (empty($tks[1])) {
            if ($throwErrors) {
                throw new \UnexpectedValueException('Wrong number of segments');
            }

            return [];
        }

        if (null === $payload = JWT::jsonDecode(JWT::urlsafeB64Decode($tks[1]))) {
            if ($throwErrors) {
                throw new \UnexpectedValueException('Invalid claims encoding');
            }
        }

        return (array) $payload;
    }

    /**
     * Delete api token by access or refresh jwt
     * Delete expired tokens: @see delete_expired
     *
     * @param string|null $jwtToken
     *
     * @return bool
     */
    public function deleteToken(string $jwtToken = null): bool
    {
        return ApiToken::deleteAll([
                'OR',
                ['access_token' => $jwtToken],
                ['refresh_token' => $jwtToken],
                // Delete expired tokens
                $this->delete_expired ? [
                    'AND',
                    ['<=', 'refresh_expires', time()],
                    ['!=', 'refresh_expires', 0],
                ] : [],
            ]) > 0;
    }
}