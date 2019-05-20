<?php

$password = '123zЯ';



$salt = '260C152FD22082DB5E875E53994CAE750B98AC372B06C516';
$password = "123zЯ";

$saltedPassword = hash_pbkdf2('sha1', $password, hex2bin($salt), 4096);
print_r('$saltedPassword: '. $saltedPassword.'<br>');


$saltedPassword = '08f09c501b671dd3ea29e010aef634f929657c74';
$clientKey = hash_hmac('SHA1',"",hex2bin($saltedPassword),0);


print_r('$clientKey: '. $clientKey.'<br>');