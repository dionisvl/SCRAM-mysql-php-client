<?php


namespace Bs\Sdk\Auth\Strategy;

class ScramAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{

    private $hashAlg;
    private $hashCount;
    private $server_nonce;
    private $signature;

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
     * @param mixed $signature
     */
    public function setSignature($signature): void
    {
        $this->signature = $signature;
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
        return $this->compute($password) ^ $this->compute($this->getServerNonce() . $this->hashPassword($password));
    }

    private function compute($mystring)
    {
        return ($this->getEncrypter())->hash($mystring, $this->getHashAlg());
    }

    /**
     * Метод для многократного хеширования
     * @param $data
     * @return mixed
     */
    private function hashPassword($data)
    {
        $i = 0;
        while ($i < $this->getHashCount()) {
            $data = $this->compute($data);
            $i++;
        }
        return $data;
    }
}