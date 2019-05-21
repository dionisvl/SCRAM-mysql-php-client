<?php

namespace Bs\Sdk\Auth\Strategy;


class MySqlAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{
    private $hashAlg;
    private $serverNonce;

    public function createClientProof($p)
    {
        //В Mysql пароль хешируется по формуле SELECT SHA1(UNHEX(SHA1('123')));
        $serverNonce = $this->getServerNonce();

        $client_proof_binary = $this->hash($p,1) ^ $this->hash(hex2bin($serverNonce.$this->hash($this->hash($p,1),0)),1);
        //$client_proof_binary = hex2bin(sha1($p)) ^ hex2bin(sha1(hex2bin($serverNonce.sha1(hex2bin(sha1($p))))));
        $client_proof_hex = bin2hex($client_proof_binary);

        /*
        print_r('$serverNonce: '.$serverNonce.'<br>');
        print_r('$client_proof_binary: '.$client_proof_binary.'<br>');
        print_r('$client_proof_hex: '.bin2hex($client_proof_binary).'<br>');*/
        return $client_proof_hex;
    }

    private function hash($mystring,$raw_output){
        return ($this->getEncryptor())->hash($mystring, $this->getHashAlg(),$raw_output);
    }

    /**
     * @param mixed $hashAlg
     */
    public function setHashAlg($hashAlg): void
    {
        $this->hashAlg = $hashAlg;
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
    public function getServerNonce()
    {
        return $this->serverNonce;
    }
}