<?php

$data = '123zЯ';

iconv(mb_detect_encoding($data, mb_detect_order(), true), "UTF-8", $data);
print_r(mb_detect_encoding($data));

$key = '260C152FD22082DB5E875E53994CAE750B98AC372B06C516';

$int1 = "\0\0\0\1";
$int1 = bin2hex($int1);
$u1 = hash_hmac('SHA1', $data, $key . $int1);

$u2 = hash_hmac('SHA1',$data, $key);

print_r('$data: '.$data.'<br>');
print_r('$key: '.$key.'<br>');

print_r('hmac($data, $key + int1): '.$u1.PHP_EOL.'<br>');
print_r('hmac($data, $key): '.$u2.PHP_EOL.'<br>');


print_r('$key + INT(1): '.$key.$int1.PHP_EOL.'<br>');



$data = '123';

$key = 'secret';
print_r('$data: '.$data.'<br>');
print_r('$key: '.$key.'<br>');

print_r('hash_hmac(\'SHA1\', $data, $key): '.hash_hmac('SHA1', $data, $key).'<br>');
print_r('hash_hmac(\'SHA1\', $data, $key): '.hash_hmac('SHA1', $data, $key).'<br>');



$data = '123zЯ';
$secret = '260C152FD22082DB5E875E53994CAE750B98AC372B06C516';
print_r('$data: '.$data.'<br>');
print_r('$secret: '.$secret.'<br>');


$int1 = "\0\0\0\1";
print_r('$int1: '.$int1.'<br>');
print_r('$secret.$int1: '.$secret.bin2hex($int1).'<br>');

$secret_int1 = $secret.bin2hex($int1);
print_r('hash_hmac(\'SHA1\', $data, $secret): '.hash_hmac('SHA1', $data, $secret).'<br>');
print_r('hash_hmac(\'SHA1\', $data, $secret_int1): '.hash_hmac('SHA1', $data, $secret_int1).'<br>');

print_r('hash_hmac(\'SHA1\', $data, hex2bin($secret)): '.hash_hmac('SHA1', $data, hex2bin($secret)).'<br>');
print_r('hash_hmac(\'SHA1\', $data, hex2bin($secret_int1)): '.hash_hmac('SHA1', $data, hex2bin($secret_int1)).'<br>');