<?php

/**
 * Клиент scram авторизации на PHP
 *
 *  - обратимся к серверу, отправим ему login чтобы он вернул serverNonce
 *  - распарсим ответ сервера и получим serverNonce + авторизационные параметры: algo, encryptor, protocolVer, iterationCount
 *  - на основе serverNonce сгенерируем client_proof
 *  - отправим серверу CP и получим ответ ок или нет.
 *
 * для scram авторизации параметры:
 * $user_login = 'admin_scram_sha1';
 * $user_password = '123zЯ';
 *
 * для Mysql параметры:
 * $user_login = 'admin_mysql_sha1';
 * $user_password = '123';
 *
 * scram sha 256:
 * логин: ĄęŚŃÓKŹ
 * пароль: ĄęŚŃÓKŹ
 *
 * scram sha 512:
 * логин: ӨҢҰФҚҒқә
 * пароль: ӨҢҰФҚҒқә
 */


require 'vendor/autoload.php';

use Bs\Sdk\Auth\Encryptors\OpensslHash;
use Bs\Sdk\Auth\Encryptors\PhpHash;
use Bs\Sdk\Auth\Strategy\AuthStrategyDispatcher;
use Bs\Sdk\Auth\Strategy\RandomString;

/* 1. Сначала сделаем handShake. Отправим логин и clientNonce на сервер */

$user_login = 'ӨҢҰФҚҒқә';
$user_password = 'ӨҢҰФҚҒқә';

$customer_key = 'qa';
$client = new GuzzleHttp\Client();

$clientNonce = (new RandomString())->handle();

//$clientNonce = "A0394B2F298F03699B97A3BD29ADCB03C375ECDD";
//$serverNonce = "9C41A03630A1AC28174401E834E21BBA2EA523D7";
//$salt = '260C152FD22082DB5E875E53994CAE750B98AC372B06C516';

print_r('client nonce: '.$clientNonce.'<br>');
try {
    $response = $client->request('POST', 'https://qa-saas.brainysoft.ru/bs-core/auth/challenge', [
        'headers' => [
            'customer-key' => $customer_key,
            'content-type' => 'application/json'
        ],
        'json' => [
            'userName' => $user_login,
            'clientNonce' => $clientNonce
        ]
    ]);
    $arr = json_decode((string)$response->getBody(), true);
    pre($arr);

} catch (\GuzzleHttp\Exception\RequestException $e) {
    pre('failed response body: ' . json_encode(json_decode($e->getResponse()->getBody()), 128 + 256));
    die('response failed!');
}

//$arr['data']['serverNonce'] = $serverNonce;
//$arr['data']['salt'] = $salt;

/* 2. исходя из ответа сервера определим стратегию клиентской аунтентификации */
$dispatcher = new AuthStrategyDispatcher();


$params['hashAlg'] = explode('_', $arr['data']['authMode'])[1];
$params['protocolVersion'] = explode('_', $arr['data']['authMode'])[0];
$params['serverNonce'] = $arr['data']['serverNonce'];//'D1CDFD86BDC80C9ABE5BE3835B13DCCB4AF7A453'
$params['encryptedServerNonce'] = $arr['data']['encryptedServerNonce'];
$params['clientNonce'] = $clientNonce;
$params['iterationCount'] = $arr['data']['iterationCount'];
$params['salt'] = $arr['data']['salt'];

pre($params);

$strategy = $dispatcher->resolveStrategy($params);

$data = array_map('trim', $_REQUEST);
if (!empty($data['encryptor'])) { //phphash or openssl
    switch ($data['encryptor']) {
        case 'openssl':
            $strategy->setEncryptor(new OpensslHash());
            break;
        case 'phphash':
            $strategy->setEncryptor(new PhpHash());
            break;
        default:
            throw new \RuntimeException('Error: Bad $encryptor version: ' . $data['encryptor']);
    }
    print_r('encryptor : ' . $data['encryptor'] . '<br>' . PHP_EOL);
} else {
    $strategy->setEncryptor(new PhpHash());
    print_r('default PhpHash encryptor  setted. <br>' . PHP_EOL);
    //throw new Exception('<<Encryptor not setted>>.');
}


/* 2.1 Сгенерируем client proof */
$client_proof = $strategy->createClientProof($user_password);
pre('$client_proof: ' . $client_proof . PHP_EOL);
//$client_proof = bin2hex($client_proof);
//pre('bin2hex($client_proof): '.$client_proof.PHP_EOL);
/* 3 отправим серверу CP На проверку */


$request = [
    'userName' => $user_login,
    'clientNonce' => $clientNonce,
    "serverNonce" => $arr['data']['serverNonce'],
    "encryptedServerNonce" => $params['encryptedServerNonce'],
    "clientProof" => $client_proof,//"рассчитанный client proof"
    "authMode" => $arr['data']['authMode']
];

pre('request: ' . json_encode($request, 128 + 256));

try {
    $response = $client->request('POST', 'https://qa-saas.brainysoft.ru/bs-core/auth/proof', [
        'headers' => [
            'customer-key' => $customer_key,
            'content-type' => 'application/json'
        ],
        'json' => $request
    ]);

    pre('body:');
    $arr = json_decode((string)$response->getBody(), true);
    pre($arr);

    pre('headers:');
    $arr = $response->getHeaders();
    pre($arr);



} catch (\GuzzleHttp\Exception\RequestException $e) {
    pre('failed response body: ' . json_encode(json_decode($e->getResponse()->getBody()), 128 + 256));
}


function pre($arr)
{
    echo '<pre>';
    echo print_r($arr, 1);
    echo '</pre>';
}
