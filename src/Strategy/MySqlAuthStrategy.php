<?php

namespace Bs\Sdk\Auth\Strategy;


class MySqlAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{

    private $hashAlg;
    private $iterationCount;
    private $serverNonce;

    /**
     * @param mixed $hashAlg
     */
    public function setHashAlg($hashAlg): void
    {
        $this->hashAlg = $hashAlg;
    }

    /**
     * @param mixed $iterationCount
     */
    public function setiterationCount($iterationCount): void
    {
        $this->iterationCount = $iterationCount;
    }

    /**
     * @param mixed $serverNonce
     */
    public function setServerNonce($serverNonce): void
    {
        $this->serverNonce = $serverNonce;
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
    public function getiterationCount()
    {
        return $this->iterationCount;
    }

    /**
     * @return mixed
     */
    public function getServerNonce()
    {
        return $this->serverNonce;
    }

    public function createClientProof($p)
    {
        //В Mysql пароль хешируется по формуле SELECT SHA1(UNHEX(SHA1('123')));
        $serverNonce = $this->getServerNonce();

        $client_proof_binary = $this->compute($p,1) ^ $this->compute(hex2bin($serverNonce.$this->compute($this->compute($p,1),0)),1);
        //$client_proof_binary = hex2bin(sha1($p)) ^ hex2bin(sha1(hex2bin($serverNonce.sha1(hex2bin(sha1($p))))));
        $client_proof_hex = bin2hex($client_proof_binary);

        return $client_proof_hex;
    }

    private function compute($mystring,$raw_output){
        return ($this->getEncryptor())->hash($mystring, $this->getHashAlg(),$raw_output);
    }
}