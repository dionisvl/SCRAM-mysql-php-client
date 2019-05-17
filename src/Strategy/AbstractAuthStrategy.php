<?php

namespace Bs\Sdk\Auth\Strategy;


abstract class AbstractAuthStrategy implements IAuthStrategy
{
    private $encryptor;

    /**
     * @return mixed
     */
    public function getEncryptor()
    {
        return $this->encryptor;
    }

    /**
     * @param mixed $encryptor
     */
    public function setEncryptor($encryptor): void
    {
        $this->encryptor = $encryptor;
    }


}