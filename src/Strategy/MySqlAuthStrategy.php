<?php

namespace Bs\Sdk\Auth\Strategy;


class MySqlAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{

    private $hashAlg;
    private $hashCount;
    private $server_nonce;

    /**
     * @param mixed $hashAlg
     */
    public function setHashAlg($hashAlg): void
    {
        $this->hashAlg = $hashAlg;
    }

    /**
     * @param mixed $hashCount
     */
    public function setHashCount($hashCount): void
    {
        $this->hashCount = $hashCount;
    }

    /**
     * @param mixed $server_nonce
     */
    public function setServerNonce($server_nonce): void
    {
        $this->server_nonce = $server_nonce;
    }



    /**
     * @return mixed
     */
    public function getHashAlg()
    {
        return $this->hashAlg;
    }

    /**
     * @return mixed
     */
    public function getHashCount()
    {
        return $this->hashCount;
    }

    /**
     * @return mixed
     */
    public function getServerNonce()
    {
        return $this->server_nonce;
    }





    public function createClientProof($password)
    {
        //В Mysql пароль хешируется по формуле SELECT SHA1(UNHEX(SHA1('123')));
        $stored_hashed_password = $this->compute($this->unhex($this->compute($password)));
        $server_nonce = $this->getServerNonce();

        print_r($server_nonce.PHP_EOL);
        print_r($stored_hashed_password.PHP_EOL);
        return $this->compute($password) ^ $this->compute($server_nonce.$stored_hashed_password);
    }

    private function compute($mystring){
        return ($this->getEncryptor())->hash($mystring, $this->getHashAlg());
    }

    /**
     * Метод для многократного хеширования
     * @param $data
     * @return mixed
     */
    private function hashPassword($data){
        $i = 0;
        while ($i<$this->getHashCount()){
            $data = $this->compute($data);
            $i++;
        }
        return $data;
    }

    private function unhex($hexstring) {
        return pack('H*', $hexstring);
    }
}