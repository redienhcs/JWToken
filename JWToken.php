<?php

namespace Redienhcs\JWToken;

class JWToken
{
    private static string $algo = 'sha256';

    /*
    iss Issuer - The issuer of the token (defaults to the request url)
    iat Issued At - When the token was issued (unix timestamp)
    exp Expiry - The token expiry date (unix timestamp)
    sub Subject - This holds the identifier for the token (defaults to user id)
    nbf Not Before - The earliest point in time that the token can be used (unix timestamp)
    jti JWT Id - A unique identifier for the token (md5 of the sub and iat claims)
    aud Audience - The intended audience for the token (not required by default)
    */
    private $required_claims = [
        'iss',
        'iat',
        'exp',
        'sub',
        'nbf',
        'jti',
        // 'aud',
    ];

    /**
     * Cria os headers para o token
     */
    private function header()
    {
        return $this->encode( [
            'alg' => self::$algo,
            'typ' => 'JWT'
        ]);
    }

    private function array_keys_exists(array $keys, array $arr) {
        return !array_diff_key(array_flip($keys), $arr);
    }     

    private function assemble( array $payload, string $secret)
    {
        if( !$this->array_keys_exists( $this->required_claims, $payload)) {
            return false;
        }

        $header = $this->header();
        $payload = $this->encode( $payload);
        $signature = self::sign($header . "." . $payload, $secret);
        return $header.'.'.$payload.'.'.$signature;
    }

    private function encode( array $input) {
        return self::base64UrlEncode( json_encode($input));
    }

    public static function generate( array $payload, string $secret) {
        return (new JWToken())->assemble( $payload, $secret);
    }

    public static function validate(string $token, string $secret)
    {
        $part = explode(".", $token);
        if (sizeof($part) != 3) {
            return false;
        }

        $header = $part[0];
        $payload = $part[1];
        $signature = $part[2];

        $valid = self::sign($header . "." . $payload, $secret);
        $payloadDecode = json_decode(base64_decode($payload), true);
        $now = strtotime('now');
        $validDate = $payloadDecode['exp'] >= $now;

        return $signature == $valid && $validDate;
    }

    private static function sign( string $input, $secret) {
        return self::base64UrlEncode(hash_hmac( self::$algo, $input, $secret, true));
    }

    private static function base64UrlEncode($text)
    {
        return str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode($text)
        );
    }
}
