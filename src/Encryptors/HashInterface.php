<?php


namespace Bs\Sdk\Auth\Encryptors;


interface HashInterface
{
    public function hash($string, $algo,$raw_output = FALSE): string;

}