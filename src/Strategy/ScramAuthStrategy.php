<?php

namespace Bs\Sdk\Auth\Strategy;


class ScramAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{

    private $hashAlg;
    private $iterationCount;
    private $serverNonce;
    private $signature;
    private $salt;
    private $clientNonce;

    /**
     * @return mixed
     */
    public function getClientNonce()
    {
        return $this->clientNonce;
    }

    /**
     * @param mixed $clientNonce
     */
    public function setClientNonce($clientNonce): void
    {
        $this->clientNonce = $clientNonce;
    }

    /**
     * @return mixed
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * @param mixed $salt
     */
    public function setSalt($salt): void
    {
        $this->salt = $salt;
    }

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
    public function setIterationCount($iterationCount): void
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
    public function getIterationCount()
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


    public function createClientProof($password)
    {
        $salt = $this->getSalt();

        $i = $this->getiterationCount();

        $algo = $this->getHashAlg();
        $clientNonce = $this->getClientNonce();
        $serverNonce = $this->getServerNonce();

        $saltedPassword = $this->hi($password, $salt, $i);

        $clientKey = hash_hmac($algo, "",$saltedPassword);
        pre('password: '.$password);
        pre('$saltedPassword: '.bin2hex($saltedPassword).'<br>');
        pre('$clientKey: '.$clientKey.'<br>');


        $storedKey = $this->compute(hex2bin($clientKey),1 );
        $authMessage = $clientNonce . $serverNonce;

        $clientSignature = hash_hmac($algo, hex2bin($authMessage),$storedKey, TRUE);

        $clientProof = hex2bin($clientKey) ^ $clientSignature;


        pre('$storedKey: '.$storedKey.'<br>');
        pre('$authMessage: '.$authMessage.'<br>');
        pre('$clientSignature: '.bin2hex($clientSignature).'<br>');
        pre('$clientProof: '.bin2hex($clientProof).'<br>');
        pre('$salt: '.$salt.'<br>');
        pre('$i: '.$i.'<br>');
        pre('$algo: '.$algo.'<br>');
        pre('$clientNonce: '.$clientNonce.'<br>');
        pre('$serverNonce: '.$serverNonce.'<br>');



        pre('hex2bin($authMessage): '.hex2bin($authMessage).'<br>');


        pre('bin2hex($clientProof): '.strtoupper (bin2hex($clientProof)).'<br>');

//        print_r('$salt: '.$salt.PHP_EOL);
//        print_r('$i: '.$i.PHP_EOL);
//        print_r('$algo: '.$algo.PHP_EOL);
//        print_r('$clientNonce: '.$clientNonce.PHP_EOL);
//        print_r('$serverNonce: '.$serverNonce.PHP_EOL);
//        print_r('$saltedPassword: '.$saltedPassword.PHP_EOL);
//        print_r('$clientKey: '.$clientKey.PHP_EOL);
//        print_r('$storedKey: '.$storedKey.PHP_EOL);
//        print_r('$authMessage: '.$authMessage.PHP_EOL);
//        print_r('$clientSignature: '.$clientSignature.PHP_EOL);
//        print_r('$clientProof: '.$clientProof.PHP_EOL);
//        print_r('bin2hex($clientProof): '.strtoupper (bin2hex($clientProof)).PHP_EOL);


        return strtoupper (bin2hex($clientProof));
    }

    private function compute($mystring,$raw_output)
    {
        return ($this->getEncryptor())->hash($mystring, $this->getHashAlg(),$raw_output);
    }

    /**
     * Hi() call, which is essentially PBKDF2 (RFC-2898) with HMAC-H() as the pseudorandom function.
     * @example : return hash_pbkdf2($algo, $data, hex2bin($key), $i);
     * @param string $str The string to hash.
     * @param string $hash The hash value.
     * @param int $i The iteration count.
     * @access private
     *
     * @return string
     */
    private function hi($data, $key, $i)
    {
        $algo = $this->getHashAlg();
        $int1 = "\0\0\0\1";
//        pre('data: '.$data);
//        pre('key: '.$key);
        $salt_int = $key.bin2hex($int1);
        //$salt_int = '260C152FD22082DB5E875E53994CAE750B98AC372B06C51600000001';

        //print_r('$salt_int: '.$key.bin2hex($int1).'<br>');
        $ui = hash_hmac($algo, hex2bin($salt_int), $data,1);//base_convert($salt_int,16,2)
        //print_r('u1: '.bin2hex($ui).'<br>');
        $result = $ui;
        for ($k = 1; $k < $i; $k++)
        {
            $ui = hash_hmac($algo,$ui,$data,1);
            $result = $result ^ $ui;
            //echo "u",$k+1,": ".bin2hex($ui).'<br>';
            //echo "result",$k+1,": ".bin2hex($result).'<br>';
            //if ($k>5) die();
        }
        return $result;
        //return hash_pbkdf2($algo, $data, hex2bin($key), $i);
    }
}