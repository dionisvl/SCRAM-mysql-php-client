<?php

/**
 * Ограниченный временный клиент scram авторизации на PHP
 *
 * Внимание, необходимо вставлять всегда свежий BSauth
 * у него время действия пол часа где то
 */


require 'vendor/autoload.php';

use Bs\Sdk\Auth\Encryptors\OpensslHash;
use Bs\Sdk\Auth\Encryptors\PhpHash;
use Bs\Sdk\Auth\Strategy\AuthStrategyDispatcher;
use Bs\Sdk\Auth\Strategy\RandomString;
use GuzzleHttp\Client;

/* 1. Сгенерируем client-proof */

$customer_key = 'qa';
$password = 'ĄęŚŃÓKŹ';
$salt = '990C152FD22082DB5E875E53994CAE750B98AC372B06C516';
$i = 10000;
$saltedPassword = hash_pbkdf2('sha512', $password, hex2bin($salt), $i);
$ClientKey = hash_hmac('SHA512',"",hex2bin($saltedPassword),0);

print_r('$password: ' . $password . '<br>');
print_r('$salt: ' . $salt . '<br>');
print_r('$i: ' . $i . '<br>');
print_r('$saltedPassword hash_pbkdf2(): ' . $saltedPassword . '<br>');
print_r('$ClientKey: ' . $ClientKey . '<br>');


print_r('-------------то что выше было рассчитано автоматически заранее, это константа------------------------- <br>');




$serviceKey = dechex(77);//it is UUID
$serviceName = 'fastmoney7';
$serviceName = implode(unpack("H*", $serviceName));

/* 2. исходя из ответа сервера определим стратегию клиентской аунтентификации */
$dispatcher = new AuthStrategyDispatcher();

$params['protocolVersion'] = 'reducedScram';
$params['clientKey'] = $ClientKey;//'D1CDFD86BDC80C9ABE5BE3835B13DCCB4AF7A453'

$params['serviceName'] = $serviceName;
$params['serviceKey'] = $serviceKey;
$params['secureRandom'] = (new RandomString(40))->handle();
$params['timestamp'] = dechex(time());

//pre('$params: ' . $params);

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
}


if (!empty($data['hashAlg'])) { //SHA1/SHA256/sha3
    $strategy->setHashAlg($data['hashAlg']);
    print_r('HashAlg : ' . $data['hashAlg'] . '<br>' . PHP_EOL);
} else {
    $strategy->setHashAlg('SHA512');
}

/* 2.1 Сгенерируем client proof */
$clientProof = $strategy->createClientProof($ClientKey);
pre('$client_proof: ' . $clientProof . PHP_EOL);
$clientProof = bin2hex($clientProof);
pre('bin2hex($clientProof): '.$clientProof.PHP_EOL);

/* 3 отправим серверу все half-scram заголовки и CP На проверку */
$headers = [
    //'Content-Type' => 'application/json',
    'customer-key' => 'qa',
    'bsauth' => 'JdNIgcGckCI2SuOBD9NSCsPXJ41JsKNLjvHFPXHSew5AN3YZVnsxOyP8mw3orh4w3AT8jFFjaaQ=',
    'service-key' => $serviceKey,
    'service-name' => $serviceName,
    'service-secret' => $params['secureRandom'],//serviceSecret
    'service-timestamp' => $params['timestamp'],
    'service-proof' => $clientProof
];

//$headers = [
//    //'Content-Type' => 'application/json',
//    //'customer-key' => 'qa',
//    'bsauth' => 'gJHlDefmBfZQs0dwM6VPb9Gv4hGozHK+MkJqZjVYqRZXxQN9YIAWIPPoGa8Orj7dmG1w9Z8QVgA=',
//    'service-key' => '77C30FDA7A799BF0D9D838D395CF9DE1E3136F65',
//    'service-name' => '666173746d6f6e657937',
//    'service-secret' => '77C30FDA7A799BF0D9D838D395CF9DE1E3136F65',
//    'service-timestamp' => '5ce7a169',
//    'service-proof' => '51b65629b65fe8af20a9bc266bc02200a68b1b016a840cd5303aa06ea5d620dcca38bc2133ea74e5f8310252320fefc6ef3b1bb7248f8daf0ab1a6c8fce9cc00'
//];

pre('$headers: ');
pre($headers);
$client = new GuzzleHttp\Client();
try {
    $response = $client->request('GET', 'https://qa-saas.brainysoft.ru/bs-core/dicts/countries', [
        'headers' => $headers
    ]);

    $arr = json_decode((string)$response->getBody(), true);
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
