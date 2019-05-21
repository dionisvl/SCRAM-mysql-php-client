<?php

namespace Bs\Sdk\Auth\Encryptors;

/**
 * https://www.php.net/manual/ru/function.openssl-digest.php
 *
 * Class OpensslHash
 * @package App\Scram
 */
class OpensslHash implements HashInterface
{
    public function hash($string, $algo,$raw_output = FALSE): string
    {
        return openssl_digest($string, $algo,$raw_output);
    }
}