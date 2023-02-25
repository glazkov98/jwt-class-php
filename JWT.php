<?php

/**
 * Class for working with JWT
 * 
 * Generates a JWT token and checks for validity
 *
 * @author Dmitry Glazkov <glazkov-official@mail.ru>
 * @version 1.0
 */
class JWT {

	/**
     * Supported algorithms
     *
     * @var array supported_algs data
     */
	private $supported_algs = [
		'HS256' => 'sha256',
		'HS384' => 'sha384',
		'HS512' => 'sha512'
	];

	/**
     * Main config
     *
     * @var array config data
     */
	private $config = [
		'alg'  => 'HS256',
		'type' => 'JWT',
		'exp'  => (3600 * 24) * 30
	];

	/**
     * Class constructor
     *
     * @param array $options class options
     */
	public function __construct($options) {
		if (!isset($options['secret'])) return false;
		
		foreach ($options as $key => $value) {
			if (isset($this->config[$key])) $this->config[$key] = $value;
		}
	}

	/**
     * JWT token generation
     *
     * @param array $payload data
     * @return string jwt token 
     */
	public function sign($payload) {
		if (!is_array($payload)) return false;

		$headers = $this->jsonEncode([
			'alg' => $this->config['alg'],
			'typ' => $this->config['type']
		]);
		$payload['iat'] = time() + $this->config['exp'];
		$payload = $this->jsonEncode($payload);

		$headers = $this->base64urlEncode($headers);
		$payload = $this->base64urlEncode($payload);
		$signature = $this->signature($headers, $payload);

		return $headers.'.'.$payload.'.'.$signature;
	}

	/**
     * JWT token verifycation
     *
     * @param string $token JWT token
     * @return array data
     */
	public function verify($token) {
		if (!$token) return false;

		$data = $this->parseToken($token);

		$headers = $this->base64urlEncode($this->jsonEncode($data['headers']));
		$payload = $this->base64urlEncode($this->jsonEncode($data['payload']));
		$signature = $this->signature($headers, $payload);

		$verify_token = $headers.'.'.$payload.'.'.$signature;

		if ($verify_token != $token) return false;

		if (time() > $data['payload']['iat']) return false;
			
		return $data['payload'];
	}

	/**
     * JWT token decode
     *
     * @param string $token JWT token
     * @return array data
     */
	public function decode($token) {
		if (!$token) return false;

		$data = $this->parseToken($token);
			
		return $data['payload'];
	}


	/**
     * Signing data with a private key
     *
     * @param string $headers JWT headers
     * @param string $payload JWT data
     * @return string base64
     */
	private function signature($headers, $payload) {
		if (!$headers || !$payload) return false;

		$alg = $this->supported_algs[$this->config['alg']];
		$secret = $this->config['secret'];

		$signature = hash_hmac($alg, $headers.'.'.$payload, $secret);
			
		return $this->base64urlEncode($signature);
	}

	/**
     * Parsing JWT token
     *
     * @param string $token JWT token
     * @return array data
     */
	private function parseToken($token) {
		if (!$token) return false;

		$data = explode('.', $token);
		$headers = $this->base64urlDecode($data[0]);
		$headers = $this->jsonDecode($headers, true);
		$payload = $this->base64urlDecode($data[1]);
		$payload = $this->jsonDecode($payload, true);

		return [
			'headers' => $headers,
			'payload' => $payload,
			'signature' => $data[2]
		];
	}

	/**
     * JSON encode data
     *
     * @param array $data encoded data
     * @return string json
     */
	private function jsonEncode($data) {
		return json_encode($data, JSON_UNESCAPED_UNICODE);
	}

	/**
     * JSON decode data
     *
     * @param string $json decoded json
     * @return array data
     */
	private function jsonDecode($json) {
		return json_decode($json, true);
	}

	/**
     * Base64 encode data
     *
     * @param string $data encoded data
     * @return string base64
     */
	private function base64urlEncode($data) {
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}

	/**
     * Base64 decode data
     *
     * @param string $data decoded base64
     * @return string data
     */
	private function base64urlDecode($data) {
		return base64_decode(strtr($data, '-_', '+/').str_repeat('=', 3 - (3 + strlen($data)) % 4));
	}

}