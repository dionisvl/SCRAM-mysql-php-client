<?php

$password = '123zЯ';
$salt = '260C152FD22082DB5E875E53994CAE750B98AC372B06C516';


$saltedPassword = hash_pbkdf2('sha1', $password, hex2bin($salt), 4096);
print_r('$saltedPassword hash_pbkdf2: '. $saltedPassword.'<br>');
print_r('$saltedPassword php custom hi: '. bin2hex(hi('sha1', $password, $salt, 4096)).'<br>');

$saltedPassword = '08f09c501b671dd3ea29e010aef634f929657c74';
$clientKey = hash_hmac('SHA1',"",hex2bin($saltedPassword),0);


print_r('$clientKey hash_hmac: '. $clientKey.'<br>');



function hi($algo, $data, $key, $i){
    $int1 = "\0\0\0\1";
    $salt_int = $key . bin2hex($int1);
    $ui = hash_hmac($algo, hex2bin($salt_int), $data, 1);
    $result = $ui;
    for ($k = 1; $k < $i; $k++) {
        $ui = hash_hmac($algo, $ui, $data, 1);
        $result = $result ^ $ui;
    }
    return $result;
}