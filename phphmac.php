<?php
/**
 * TERMINAL APPLICATION: PHP EXAMPLE: OPENSSL HMAC: ENCRYPT / DECRYPT
 *
 * SOURCE CODE: https://gist.github.com/xxalfa/bfce04823da603968c38c8884fb0a553
 */
//-------------------------------------------------
// HEAD
//-------------------------------------------------
declare( strict_types = 1 );
header( 'Content-Type:text/plain' );
isset( $argv ) or die( 'This is a terminal application.' . PHP_EOL );
extension_loaded( 'openssl' ) or die( 'The openssl extension is required.' . PHP_EOL );
error_reporting( -1 );
ini_set( 'display_errors', '1' );
ini_set( 'html_errors', '0' );
define( 'CORE_DIR', dirname( __FILE__ ) . DIRECTORY_SEPARATOR );
function is_tty( $value ) { return function_exists( 'posix_isatty' ) ? $value : ''; }
//-------------------------------------------------
// FUNCTIONS
//-------------------------------------------------
function text_encrypt_contents( $cipher_method, $key, $plaintext ): string
{
    $initialization_vector_length = openssl_cipher_iv_length( $cipher_method );
    $initialization_vector = openssl_random_pseudo_bytes( $initialization_vector_length );
    $encrypted_data = openssl_encrypt( $plaintext, $cipher_method, $key, $options = OPENSSL_RAW_DATA, $initialization_vector );
    $hmac = hash_hmac( 'sha256', $encrypted_data, $key, $as_binary = true );
    $ciphertext = $initialization_vector . $hmac . $encrypted_data;
    return $ciphertext;
}
function text_decrypt_contents( $cipher_method, $key, $ciphertext ): string
{
    $initialization_vector_length = openssl_cipher_iv_length( $cipher_method );
    $initialization_vector = substr( $ciphertext, 0, $initialization_vector_length );
    $hmac = substr( $ciphertext, $initialization_vector_length, $sha256_length = 32 );
    $ciphertext = substr( $ciphertext, $initialization_vector_length + $sha256_length );
    $recalculated_hmac = hash_hmac( 'sha256', $ciphertext, $key, $as_binary = true );
    hash_equals( $hmac, $recalculated_hmac ) or die ( 'PHP 5.6+ timing attack safe comparison failed.' . PHP_EOL );
    $decrypted_data = openssl_decrypt( $ciphertext, $cipher_method, $key, $options = OPENSSL_RAW_DATA, $initialization_vector );
    return $decrypted_data;
}
//-------------------------------------------------
// TEST
//-------------------------------------------------
$cipher_method = 'CAMELLIA-256-OFB';
$initialization_vector_length = openssl_cipher_iv_length( $cipher_method );
$key = openssl_random_pseudo_bytes( $initialization_vector_length );
echo 'KEY -- ' . bin2hex( $key ) . PHP_EOL;
$plaintext = 'my message';
echo 'PLAINTEXT -- ' . $plaintext . PHP_EOL;
$ciphertext = text_encrypt_contents( $cipher_method, $key, $plaintext );
echo 'ENCRYPT -- ' . base64_encode( $ciphertext ) . PHP_EOL;
$decrypted_data = text_decrypt_contents( $cipher_method, $key, $ciphertext );
echo 'DECRYPT -- ' . $decrypted_data . PHP_EOL;
