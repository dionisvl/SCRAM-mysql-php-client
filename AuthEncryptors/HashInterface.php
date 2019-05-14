<?php


namespace AuthEncryptors;


interface HashInterface
{
    public function hash($string, $algo): string;

}