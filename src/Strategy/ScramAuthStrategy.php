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

        $clientKey = hash_hmac($algo,$saltedPassword, "", TRUE);

        $storedKey = $this->compute($clientKey, TRUE);
        $authMessage = $clientNonce . $serverNonce;

        $clientSignature = hash_hmac($algo, $storedKey, hex2bin($authMessage), TRUE);

        $clientProof = $clientKey ^ $clientSignature;

        pre('password: '.$password);
        pre('$saltedPassword: '.bin2hex($saltedPassword).'<br>');
        pre('$salt: '.$salt.'<br>');
        pre('$i: '.$i.'<br>');
        pre('$algo: '.$algo.'<br>');
        pre('$clientNonce: '.$clientNonce.'<br>');
        pre('$serverNonce: '.$serverNonce.'<br>');
        pre('$clientKey: '.bin2hex($clientKey).'<br>');
        pre('$storedKey: '.$storedKey.'<br>');
        pre('$authMessage: '.$authMessage.'<br>');
        pre('hex2bin($authMessage): '.hex2bin($authMessage).'<br>');
        pre('$clientSignature: '.$clientSignature.'<br>');
        pre('$clientProof: '.$clientProof.'<br>');
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
     *
     * @param string $str The string to hash.
     * @param string $hash The hash value.
     * @param int $i The iteration count.
     * @access private
     *
     * @return string
     */
    private function hi($str, $salt, $i)
    {
        $algo = $this->getHashAlg();

        pre($str);
        pre($salt);


        $int1 = "\0\0\0\1";
        $int1 = bin2hex($int1);
        $ui = hash_hmac($algo, $str, hex2bin($salt . $int1), 0);
        pre('$ui FIRST: '.bin2hex($ui).'<br>');
        $result = $ui;
        for ($k = 1; $k < $i; $k++)
        {
            $ui = hash_hmac($algo, $str, $ui, 0);
            $result = $result ^ $ui;

            pre("u$k: ".bin2hex($result).'<br>');

            if ($k>5) break;
        }
        return $result;
    }
}