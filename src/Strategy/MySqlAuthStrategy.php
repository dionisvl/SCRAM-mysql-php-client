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

    public function createClientProof($p)
    {
        //В Mysql пароль хешируется по формуле SELECT SHA1(UNHEX(SHA1('123')));
        $nonce = $this->getServerNonce();

        $client_proof_binary = $this->compute($p,1) ^ $this->compute(hex2bin($nonce.$this->compute($this->compute($p,1),0)),1);
        //$client_proof_binary = hex2bin(sha1($p)) ^ hex2bin(sha1(hex2bin($nonce.sha1(hex2bin(sha1($p))))));
        $client_proof_hex = bin2hex($client_proof_binary);

        return $client_proof_hex;
    }

    private function compute($mystring,$raw_output){
        return ($this->getEncryptor())->hash($mystring, $this->getHashAlg(),$raw_output);
    }
}