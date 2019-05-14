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


/* 1. Сначала сделаем handShake. Отправим на сервер логин */

$user_login = 'test_login';
$user_password = 'test_password';

$client = new GuzzleHttp\Client();


$res = $client->request('GET', 'http://httpbin.org', [
    'user_login' => $user_login
]);

$body = $res->getBody();

/* 2. исходя из ответа сервера определим стратегию клиентской аунтентификации */
$strategy = (new AuthStrategyDispatcher())->resolveStrategy($body);
/* 2.1 Сгенерируем client proof */
$client_proof = $strategy->createClientProof($user_password);

/* 3 отправим серверу CP На проверку */
$res = $client->request('GET', 'http://httpbin.org', [
    'user_login' => $user_login,
    'client_proof' => $client_proof
]);

$body = $res->getBody();

