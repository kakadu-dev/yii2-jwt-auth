<?php
/**
 * Created by PhpStorm.
 * User: mikhail
 * Date: 23.10.2018
 * Time: 16:52
 */

namespace Kakadu\Yii2JwtAuth;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use UnexpectedValueException;
use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\db\Exception;
use yii\di\Instance;
use yii\log\Dispatcher;
use yii\log\Logger;

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
    public $audience;

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
    public $seamlessLogin = true;

    /**
     * Auto delete expired token
     *
     * @var bool
     */
    public $deleteExpired = true;

    /**
     * @var Dispatcher|string|null
     */
    public $log = 'log';

    /**
     * @var string
     */
    public $logCategory = 'jwt-auth';

    /**
     * ApiTokenService constructor.
     *
     * @param array $config
     *
     * @throws InvalidConfigException
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        if ($this->log !== null) {
            $this->log = Instance::ensure($this->log, Dispatcher::class);
        }
    }


    /**
     * Create api token
     *
     * @param int   $userId
     * @param array $params
     *
     * @return ApiToken|null
     * @throws Exception
     */
    public function create(int $userId, array $params = []): ?ApiToken
    {
        $issuer   = $this->getIssuer();
        $audience = $this->getAudience();

        $accessExpires  = 0;
        $refreshExpires = 0;

        $params['user_id'] = $userId;

        if ($issuer) {
            $params['iss'] = $issuer;
        }

        if ($audience) {
            $params['aud'] = $audience;
        }

        if ($this->expiration) {
            $accessExpires = time() + $this->expiration;
            $params['exp'] = $accessExpires;
        }

        $jwtRefreshParams = [
            'user_id'      => $userId,
            'refreshToken' => true,
        ];

        if ($this->expirationRefresh) {
            $refreshExpires          = time() + $this->expirationRefresh;
            $jwtRefreshParams['exp'] = $refreshExpires;
        }

        $newToken = new ApiToken([
            'user_id'         => $userId,
            'access_token'    => JWT::encode($params, $this->getSecretKey(), $this->alg),
            'refresh_token'   => JWT::encode($jwtRefreshParams, $this->getSecretKey(), $this->alg),
            'access_expires'  => $accessExpires,
            'refresh_expires' => $refreshExpires,
        ]);

        $existedToken = $this->findExistedToken($newToken);
        if ($existedToken !== null) {
            return $existedToken;
        }

        if (!$newToken->validate()) {
            $this->log(sprintf('new token not saved due errors: `%s`', json_encode($newToken->errors)), Logger::LEVEL_WARNING);

            return null;
        }

        ApiToken::getDb()->createCommand()
            ->upsert(ApiToken::tableName(), $newToken->attributes, $newToken->attributes)
            ->execute();

        return $this->findExistedToken($newToken);
    }

    /**
     * Search existed token. Useful for concurrent requests
     *
     * @param ApiToken $token
     *
     * @return ApiToken|null
     */
    private function findExistedToken(ApiToken $token): ?ApiToken
    {
        return ApiToken::findOne([
            'user_id'         => $token->user_id,
            'access_token'    => $token->access_token,
            'refresh_expires' => $token->refresh_expires,
        ]);
    }

    /**
     * Get secret key
     *
     * @return string|null
     */
    private function getSecretKey(): ?string
    {
        return $this->getConfigValue($this->secretKey);
    }

    /**
     * Get jwt issuer
     *
     * @return string|null
     */
    private function getIssuer(): ?string
    {
        return $this->getConfigValue($this->issuer);
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
            $audience = array_map(function ($value) {
                return $this->getConfigValue($value);
            }, $audience);
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
                unset($audienceSecrets[$item]);
                $audienceSecrets[Yii::$app->params[$inParams[1]] ?? $item] = $value;
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
     * @throws Exception
     */
    public function renewJwtToken(JwtToken $accessToken, JwtToken $refreshToken): ?ApiToken
    {
        if ($accessToken->isInvalid()) {
            $this->log(sprintf('access token for user#%d is invalid', $accessToken->getUserID()), Logger::LEVEL_WARNING);

            return null;
        }
        if ($refreshToken->isInvalid()) {
            $this->log(sprintf('refresh token for user#%d is invalid', $accessToken->getUserID()), Logger::LEVEL_WARNING);

            return null;
        }
        if ($refreshToken->isExpired()) {
            $this->log(sprintf('refresh token for user#%d is expired', $accessToken->getUserID()), Logger::LEVEL_PROFILE);

            return null;
        }

        $oldToken = ApiToken::findOne(['access_token' => $accessToken->getJwtToken()]);
        if ($oldToken === null) {
            $this->log(sprintf('old access token for user#%d not found', $accessToken->getUserID()), Logger::LEVEL_PROFILE);

            return null;
        }
        if ($oldToken->refresh_token !== $refreshToken->getJwtToken()) {
            $this->log('wrong refresh token', Logger::LEVEL_WARNING);

            return null;
        }

        $this->deleteToken($refreshToken->getJwtToken());

        $userID = $accessToken->getUserID();
        $params = $accessToken->getJwtDecodedToken();

        return $this->create($userID, $params);
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
            throw new UnexpectedValueException('Empty jwt');
        }

        $secretKey = $this->getSecretKey();

        // Check audience
        if ($this->getAudience() !== false) {
            $payload = $this->getJwtPayload($jwtToken);

            $issuer   = $this->getIssuer();
            $allowAud = $payload['aud'] ?? null;

            if ((is_string($allowAud) && $allowAud !== $issuer)
                || (is_array($allowAud) && !in_array($issuer, $allowAud, true))
            ) {
                throw new UnexpectedValueException('Invalid issuer');
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
                throw new UnexpectedValueException('Wrong number of segments');
            }

            return [];
        }

        $payload = JWT::jsonDecode(JWT::urlsafeB64Decode($tks[1]));
        if ($payload === null && $throwErrors) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }

        return (array) $payload;
    }

    /**
     * Delete api token by access or refresh jwt
     * Delete expired tokens: @see deleteExpired
     *
     * @param string|null $jwtToken
     *
     * @return int number of deleted tokens, may be 0
     */
    public function deleteToken(string $jwtToken = null): int
    {
        return ApiToken::deleteAll([
            'OR',
            ['access_token' => $jwtToken],
            ['refresh_token' => $jwtToken],
            // Delete expired tokens
            $this->deleteExpired ? [
                'AND',
                ['<=', 'refresh_expires', time()],
                ['!=', 'refresh_expires', 0],
            ] : [],
        ]);
    }

    /**
     * @param string $message
     * @param int    $level
     */
    private function log(string $message, int $level): void
    {
        if ($this->log === null) {
            return;
        }

        $this->log->logger->log($message, $level, $this->logCategory);
    }

    /**
     * Parse value and return itself or real value from `Yii::$app->params`
     *
     * @param string $value
     *
     * @return mixed
     */
    private function getConfigValue($value)
    {
        $inParams = explode('yii-params.', $value);

        if (!empty($inParams[1])) {
            return Yii::$app->params[$inParams[1]] ?? $value;
        }

        return $value;
    }
}
