<?php

namespace QQConnect;

use think\facade\Config;

class QQConnect
{
    protected string $appId;
    protected string $appKey;
    protected string $callbackUrl;
    protected string $scope;
    protected ?string $accessToken = null;
    protected ?string $openId = null;

    const AUTH_URL = 'https://graph.qq.com/oauth2.0/authorize';
    const TOKEN_URL = 'https://graph.qq.com/oauth2.0/token';
    const OPENID_URL = 'https://graph.qq.com/oauth2.0/me';
    const USER_INFO_URL = 'https://graph.qq.com/user/get_user_info';

    public function __construct(?array $config = null)
    {
        $config = $config ?? Config::get('qqlogin');
        $this->appId = (string)($config['app_id'] ?? '');
        $this->appKey = (string)($config['app_key'] ?? '');
        $this->callbackUrl = (string)($config['callback_url'] ?? '');
        $this->scope = (string)($config['scope'] ?? 'get_user_info');
    }

    public function setAccessToken(string $token): static
    {
        $this->accessToken = $token;
        return $this;
    }

    public function setOpenId(string $openId): static
    {
        $this->openId = $openId;
        return $this;
    }

    public function getAuthorizeUrl(?string $state = null): array
    {
        $state = $state ?? bin2hex(random_bytes(16));

        $url = self::AUTH_URL . '?' . http_build_query([
            'response_type' => 'code',
            'client_id'     => $this->appId,
            'redirect_uri'  => $this->callbackUrl,
            'state'         => $state,
            'scope'         => $this->scope,
        ]);

        return ['url' => $url, 'state' => $state];
    }

    public function getAccessToken(string $code): string
    {
        $params = [
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->appId,
            'client_secret' => $this->appKey,
            'code'          => $code,
            'redirect_uri'  => $this->callbackUrl,
        ];

        $response = $this->httpGet(self::TOKEN_URL . '?' . http_build_query($params));

        if (str_contains($response, 'callback')) {
            $error = $this->parseCallback($response);
            throw new QQConnectException($error['error_description'] ?? '获取access_token失败', $error['error'] ?? -1);
        }

        parse_str($response, $result);

        if (empty($result['access_token'])) {
            throw new QQConnectException('获取access_token失败: 返回数据异常');
        }

        $this->accessToken = $result['access_token'];
        return $this->accessToken;
    }

    public function getOpenId(): string
    {
        $this->ensureAccessToken();

        $response = $this->httpGet(self::OPENID_URL . '?' . http_build_query([
            'access_token' => $this->accessToken,
        ]));

        $result = $this->parseCallback($response);

        if (isset($result['error'])) {
            throw new QQConnectException($result['error_description'] ?? '获取openid失败', $result['error']);
        }

        if (empty($result['openid'])) {
            throw new QQConnectException('获取openid失败: 返回数据异常');
        }

        $this->openId = $result['openid'];
        return $this->openId;
    }

    public function getUserInfo(): array
    {
        $this->ensureAccessToken();
        $this->ensureOpenId();

        $params = [
            'access_token'       => $this->accessToken,
            'oauth_consumer_key' => $this->appId,
            'openid'             => $this->openId,
            'format'             => 'json',
        ];

        $response = $this->httpGet(self::USER_INFO_URL . '?' . http_build_query($params));
        $result = json_decode($response, true);

        if ($result === null) {
            throw new QQConnectException('获取用户信息失败: JSON解析错误');
        }

        if (($result['ret'] ?? -1) != 0) {
            throw new QQConnectException($result['msg'] ?? '获取用户信息失败', $result['ret'] ?? -1);
        }

        return $result;
    }

    public function refreshToken(string $refreshToken): string
    {
        $params = [
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->appId,
            'client_secret' => $this->appKey,
            'refresh_token' => $refreshToken,
        ];

        $response = $this->httpGet(self::TOKEN_URL . '?' . http_build_query($params));

        if (str_contains($response, 'callback')) {
            $error = $this->parseCallback($response);
            throw new QQConnectException($error['error_description'] ?? '刷新token失败', $error['error'] ?? -1);
        }

        parse_str($response, $result);

        if (empty($result['access_token'])) {
            throw new QQConnectException('刷新token失败: 返回数据异常');
        }

        $this->accessToken = $result['access_token'];
        return $this->accessToken;
    }

    protected function parseCallback(string $response): array
    {
        if (preg_match('/callback\(\s*(.+?)\s*\)/s', $response, $matches)) {
            $json = json_decode($matches[1], true);
            if ($json !== null) {
                return $json;
            }
        }
        return [];
    }

    protected function httpGet(string $url): string
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        ]);

        $response = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($errno) {
            throw new QQConnectException("HTTP请求失败: {$error}", $errno);
        }

        return $response;
    }

    protected function ensureAccessToken(): void
    {
        if (empty($this->accessToken)) {
            throw new QQConnectException('access_token未设置，请先调用getAccessToken()');
        }
    }

    protected function ensureOpenId(): void
    {
        if (empty($this->openId)) {
            throw new QQConnectException('openid未设置，请先调用getOpenId()');
        }
    }
}
