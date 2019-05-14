<?php


abstract class AbstractAuthStrategy implements IAuthStrategy
{
    private $encrypter;

    /**
     * @return mixed
     */
    public function getEncrypter()
    {
        return $this->encrypter;
    }

    /**
     * @param mixed $encrypter
     */
    public function setEncrypter($encrypter): void
    {
        $this->encrypter = $encrypter;
    }


}