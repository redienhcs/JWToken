<?php

require_once('JWToken.php');

use Redienhcs\JWToken\JWToken;

$tokenValidity = 3600; // In seconds
$dataExpedicao = date('Y-m-d H:i:s');
$dataExpiracao = date('Y-m-d H:i:s', strtotime( $dataExpedicao . ' + '.$tokenValidity.' seconds'));

//https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
$claims['iss']  = 'Nome of the application';            //Issuer of the token
$claims['sub']  = 1;                                    //Subject of the token - Unique id of the subject
$claims['exp']  = strtotime( $dataExpiracao);           //Expiration
$claims['nbf']  = strtotime( $dataExpedicao);           //Not before - Do not accept before
$claims['iat']  = strtotime( $dataExpedicao);           //Issued at
$claims['jti']  = md5( $claims['sub'].$claims['iat']);  //JWT ID
//Custom claims
$claims['teste']  = 'Valor de teste';

$segredo = sha1('A very long secret kept at the cost of many lives');
$token = JWToken::generate( $claims, $segredo);

echo 'Token gerado: '.PHP_EOL;
echo $token;
echo PHP_EOL;
echo 'Data validade do token: '.$dataExpiracao.PHP_EOL;
echo PHP_EOL;
echo 'Assinatura verificada: '. ( ( JWToken::validate( $token ,  $segredo) ) ? 'sim': 'Não');
echo PHP_EOL;

$token1 = $token;

$part = explode(".", $token);

if (sizeof($part) != 3) {
return false;
}
$header = $part[0];
$payload = $part[1];
$signature = $part[2];
$payloadDecode = json_decode(base64_decode($payload), true);
$payloadDecode['teste']  = 'Valor alterado';


$token = $header.'.'.str_replace(
    ['+', '/', '='],
    ['-', '_', ''],
    base64_encode( json_encode( $payloadDecode))).'.'.$signature;


$token2 = $token;

echo 'Token gerado: '.PHP_EOL;
echo $token;
echo PHP_EOL;
echo 'Data validade do token: '.$dataExpiracao.PHP_EOL;
echo PHP_EOL;
echo 'Assinatura verificada: '. ( ( JWToken::validate( $token ,  $segredo) ) ? 'sim': 'Não');
echo PHP_EOL;

echo 'Iguais: '.( ( $token1 == $token2) ? 'sim': 'Não');
echo PHP_EOL;
