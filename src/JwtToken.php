<?php
/**
 * Created by PhpStorm.
 * User: mikhail
 * Date: 24.10.2018
 * Time: 10:26
 */

namespace Kakadu\Yii2JwtAuth;

/**
 * Class    JwtToken
 * @package Kakadu\Yii2JwtAuth
 * @author  Yarmaliuk Mikhail
 * @version 1.0
 */
class JwtToken
{
    /**
     * @var string
     */
    private $_jwtToken;

    /**
     * @var array
     */
    private $_jwtDecodedToken;

    /**
     * @var bool
     */
    private $_isExpired = false;

    /**
     * @var bool
     */
    private $_isInvalid = false;

    /**
     * Get decoded jwt token
     *
     * @return array
     */
    public function getJwtDecodedToken(): array
    {
        return (array) $this->_jwtDecodedToken;
    }

    /**
     * Set decoded jwt token
     *
     * @param array $jwtToken
     *
     * @return self
     */
    public function setJwtDecodedToken(array $jwtToken): self
    {
        $this->_jwtDecodedToken = $jwtToken;

        return $this;
    }

    /**
     * Set expired jwt token
     *
     * @param bool $isExpired
     *
     * @return self
     */
    public function setIsExpired(bool $isExpired): self
    {
        $this->_isExpired = $isExpired;

        return $this;
    }

    /**
     * Is expired jwt token
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        return $this->_isExpired;
    }

    /**
     * Set invalid jwt token
     *
     * @param bool $isInvalid
     *
     * @return JwtToken
     */
    public function setIsInvalid(bool $isInvalid): JwtToken
    {
        $this->_isInvalid = $isInvalid;

        return $this;
    }

    /**
     * Is invalid jwt token
     *
     * @return bool
     */
    public function isInvalid(): bool
    {
        return $this->_isInvalid;
    }

    /**
     * Get user id
     *
     * @return int
     */
    public function getUserID(): int
    {
        return $this->_jwtDecodedToken['user_id'] ?? 0;
    }

    /**
     * Is access token
     *
     * @return bool
     */
    public function isAccessToken(): bool
    {
        return !array_key_exists('refreshToken', $this->_jwtDecodedToken);
    }

    /**
     * Is refresh token
     *
     * @return bool
     */
    public function isRefreshToken(): bool
    {
        return array_key_exists('refreshToken', $this->_jwtDecodedToken) &&
            $this->_jwtDecodedToken['refreshToken'];
    }

    /**
     * Set jwt token string
     *
     * @param string|null $jwtToken
     *
     * @return JwtToken
     */
    public function setJwtToken(string $jwtToken = null): JwtToken
    {
        $this->_jwtToken = $jwtToken;

        return $this;
    }

    /**
     * Get jwt token string
     *
     * @return string|null
     */
    public function getJwtToken(): ?string
    {
        return $this->_jwtToken;
    }
}