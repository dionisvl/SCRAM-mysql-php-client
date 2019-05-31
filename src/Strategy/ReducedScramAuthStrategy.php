<?php


namespace Bs\Sdk\Auth\Strategy;


class ReducedScramAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{
    private $hashAlg;

    private $serviceName;
    private $serviceKey;
    private $serviceNonce;
    private $timestamp;

    public function createClientProof($clientKey)
    {
        $algo = $this->getHashAlg();
        $serviceKey = $this->getServiceKey();
        $serviceName = $this->getServiceName();
        $serviceNonce = $this->getServiceNonce();//serviceNonce
        $timestamp = $this->getTimestamp();

        $authMessage = $timestamp . $serviceNonce . $serviceKey . $serviceName;
        $authMessage = hex2bin($authMessage);

        $storedKey = $this->hash(hex2bin($clientKey), 1);

        $clientSignature = hash_hmac($algo,  $authMessage,$storedKey, 1);

        $clientProof = hex2bin($clientKey) ^ $clientSignature;

        print_r('$serviceNonce: ' . $serviceNonce . '<br>');
        print_r('$timestamp: ' . $timestamp . '<br>');
        print_r('$authMessage=$timestamp + $serviceNonce + $serviceKey + $serviceName = ' . bin2hex($authMessage) . '<br>');


        print_r('$clientKey: ' . $clientKey . '<br>');

        print_r('$storedKey: ' . bin2hex($storedKey) . '<br>');
        print_r('$clientSignature: ' . bin2hex($clientSignature) . '<br>');
        print_r('$clientProof: ' . bin2hex($clientProof) . '<br>');


        return $clientProof;

    }

    private function hash($mystring, $raw_output)
    {
        return ($this->getEncryptor())->hash($mystring, $this->getHashAlg(), $raw_output);
    }



    /**
     * @return mixed
     */
    public function getServiceNonce()
    {
        return $this->serviceNonce;
    }

    /**
     * @param mixed $secureRandom
     */
    public function setServiceNonce($serviceNonce): void
    {
        $this->serviceNonce = $serviceNonce;
    }

    /**
     * @return mixed
     */
    public function getTimestamp()
    {
        return $this->timestamp;
    }

    /**
     * @param mixed $timestamp
     */
    public function setTimestamp($timestamp): void
    {
        $this->timestamp = $timestamp;
    }

    /**
     * @return mixed
     */
    private function getHashAlg()
    {
        return $this->hashAlg;
    }

    /**
     * @return mixed
     */
    public function setHashAlg($hashAlg): void
    {
        $this->hashAlg = $hashAlg;
    }

    /**
     * @return mixed
     */
    public function getServiceKey()
    {
        return $this->serviceKey;
    }

    /**
     * @param mixed $serviceKey
     */
    public function setServiceKey($serviceKey): void
    {
        $this->serviceKey = $serviceKey;
    }

    /**
     * @return mixed
     */
    public function getServiceName()
    {
        return $this->serviceName;
    }

    /**
     * @param mixed $serviceName
     */
    public function setServiceName($serviceName): void
    {
        $this->serviceName = $serviceName;
    }


}