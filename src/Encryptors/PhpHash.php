<?php

namespace Bs\Sdk\Auth\Encryptors;

/**
 * https://www.php.net/manual/ru/function.hash.php
 *
 * Class PhpHash
 * @package App\Scram
 */
class PhpHash implements HashInterface
{
    public function hash($string, $algo,$raw_output = FALSE): string
    {
        return hash($algo, $string,$raw_output);
    }
}