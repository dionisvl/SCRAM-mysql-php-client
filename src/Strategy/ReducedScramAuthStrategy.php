<?php


namespace Bs\Sdk\Auth\Strategy;

use Bs\Sdk\Auth\Strategy\RandomString;


class ReducedScramAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{
    private $hashAlg;

    private $serviceName;
    private $serviceKey;
    private $secureRandom;
    private $timestamp;

    public function createClientProof($clientKey)
    {
        $algo = $this->getHashAlg();
        $serviceKey = $this->getServiceKey();
        $serviceName = $this->getServiceName();
        $secureRandom = $this->getSecureRandom();//serviceSecret
        $timestamp = $this->getTimestamp();

        $authMessage = $timestamp . $secureRandom . $serviceKey . $serviceName;
        //$authMessage = 'A0394B2F298F03699B97A3BD29ADCB03C375ECDD9C41A03630A1AC28174401E834E21BBA2EA523D7';
        $authMessage = hex2bin($authMessage);

        $storedKey = $this->hash(hex2bin($clientKey), 1);

        $clientSignature = hash_hmac($algo,  $authMessage,$storedKey, 1);

        $clientProof = hex2bin($clientKey) ^ $clientSignature;


        print_r('$algo: ' . $algo . '<br>');
        print_r('$ServiceKey: ' . $this->getServiceKey() . '<br>');
        print_r('$serviceName: ' . $serviceName . '<br>');
        print_r('$secureRandom(serviceSecret): ' . $secureRandom . '<br>');
        print_r('$timestamp: ' . $timestamp . '<br>');
        print_r('$authMessage=$timestamp + $secureRandom(serviceSecret) + $serviceKey + $serviceName = ' . bin2hex($authMessage) . '<br>');


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
    public function getSecureRandom()
    {
        return $this->secureRandom;
    }

    /**
     * @param mixed $secureRandom
     */
    public function setSecureRandom($secureRandom): void
    {
        $this->secureRandom = $secureRandom;
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