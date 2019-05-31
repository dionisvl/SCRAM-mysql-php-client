<?php




$password = 'ПарольТранзитныйABC';
$salt = '17CB8A11B01A10BE1FD3120FCA640F39FA013020C972A082';
$iterationCount = 5382;

$saltedPassword = hash_pbkdf2('sha256', $password, hex2bin($salt), $iterationCount);
print_r('$saltedPassword hash_pbkdf2: '. $saltedPassword.'<br>');


$clientKey = hash_hmac('sha256',"",hex2bin($saltedPassword),0);
print_r('$clientKey hash_hmac: '. $clientKey.'<br>');