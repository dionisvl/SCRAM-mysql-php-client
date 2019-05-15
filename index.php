<?php


/**
 * Клиент scram авторизации на PHP
 *
 *  - обратимся к серверу, отправим ему login чтобы он вернул server_nonce
 *  - распарсим ответ сервера и получим server_nonce + авторизационные параметры: algo, encrypter, protocolVer, hashCount
 *  - на основе server_nonce сгенерируем client_proof
 *  - отправим серверу CP и получим ответ ок или нет.
 */


require 'vendor/autoload.php';
use Bs\Sdk\Auth\Strategy\AuthStrategyDispatcher;

/* 1. Сначала сделаем handShake. Отправим на сервер логин */

$user_login = 'admin_mysql_sha1';
$user_password = '123';

$customer_key = 'qa';
$client = new GuzzleHttp\Client();



$response = $client->request('POST', 'http://172.16.10.62:8082/bs-core/auth/first-message', [
    'headers' => [
        'customer-key' => $customer_key,
        'content-type' => 'application/json'
    ],
    'json' => ['userKey' => $user_login]
]);

$arr = json_decode((string)$response->getBody(), true);
pre($arr);

$params['hashAlg'] = explode('_',$arr['data']['authMode'])[1];
$params['protocolVersion'] = explode('_',$arr['data']['authMode'])[0];
$params['nonce'] = $arr['data']['nonce'];//'D1CDFD86BDC80C9ABE5BE3835B13DCCB4AF7A453';
$params['encryptedNonce'] = $arr['data']['encryptedNonce'];
$params['encrypter'] = 'openssl';



pre('$params[\'hashAlg\']: '.$params['hashAlg']);

/* 2. исходя из ответа сервера определим стратегию клиентской аунтентификации */
$dispatcher = new AuthStrategyDispatcher();
$strategy = $dispatcher->resolveStrategy($params);
/* 2.1 Сгенерируем client proof */
$client_proof = $strategy->createClientProof($user_password);
pre('$client_proof: '.$client_proof.PHP_EOL);
$client_proof = bin2hex($client_proof);
pre('bin2hex($client_proof): '.$client_proof.PHP_EOL);
/* 3 отправим серверу CP На проверку */



$request = [
    'userKey' => $user_login,
    "nonce" => $arr['data']['nonce'],
    "encryptedNonce" => $params['encryptedNonce'],
    "clientProof" => $client_proof,//"рассчитанный client proof"
    "authMode" => 'MYSQL_SHA1'
];

pre('request: '.json_encode($request, 128 + 256));

try {
    $response = $client->request('POST', 'http://172.16.10.62:8082/bs-core/auth/final-message', [
        'headers' => [
            'customer-key' => $customer_key,
            'content-type' => 'application/json'
        ],
        'json' => $request
    ]);
} catch (\GuzzleHttp\Exception\RequestException $e) {
    pre(': '.json_encode(json_decode($e->getResponse()->getBody()), 128 + 256));
}


function pre($arr){
    echo '<pre>';
    echo print_r($arr,1);
    echo '</pre>';
}

function String2Hex($string){
    return implode(unpack("H*", $string));
}

function hexToStr($hex){//должно работать так же как и hex2bin ( string $data ) : string
    return pack("H*", $hex);
}