<?php

namespace Bs\Sdk\Auth\Strategy;


class ScramAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{
    private $hashAlg;
    private $iterationCount;
    private $serverNonce;
    private $salt;
    private $clientNonce;

    public function createClientProof($password)
    {
        $salt = $this->getSalt();
        $i = $this->getiterationCount();
        $algo = $this->getHashAlg();
        $clientNonce = $this->getClientNonce();
        $serverNonce = $this->getServerNonce();


        $saltedPassword = $this->hi($algo, $password, $salt, $i);
        $clientKey = hash_hmac($algo, "", $saltedPassword, 0);
        $storedKey = $this->hash(hex2bin($clientKey), 1);
        $authMessage = $clientNonce . $serverNonce;
        $clientSignature = hash_hmac($algo, hex2bin($authMessage), $storedKey, 1);
        $clientProof = hex2bin($clientKey) ^ $clientSignature;


        /*
        print_r('$salt: '.$salt.'<br>');
        print_r('$clientNonce: '.bin2hex($clientNonce).'<br>');
        print_r('$serverNonce: '.bin2hex($serverNonce).'<br>');
        print_r('$saltedPassword: '.bin2hex($saltedPassword).'<br>');
        print_r('$clientKey: '.$clientKey.'<br>');
        print_r('$storedKey: '.bin2hex($storedKey).'<br>');
        print_r('$authMessage: '.$authMessage.'<br>');
        print_r('$clientSignature: '.bin2hex($clientSignature).'<br>');
        print_r('$clientProof: '.bin2hex($clientProof).'<br>');
*/
        return strtoupper(bin2hex($clientProof));
    }

    private function hash($mystring, $raw_output)
    {
        return ($this->getEncryptor())->hash($mystring, $this->getHashAlg(), $raw_output);
    }

    /** Hi() call, which is essentially PBKDF2 (RFC-2898) with HMAC-H() as the pseudorandom function.
     * PBKDF2 example : return hash_pbkdf2($algo, $data, hex2bin($key), $i,20,1);
     * @param string $str The string to hash.
     * @param string $hash The hash value.
     * @param int $i The iteration count.
     * @access private
     *
     * @return string
     */
    private function hi($algo, $data, $key, $i)
    {
        $int1 = "\0\0\0\1";
        $salt_int = $key . bin2hex($int1);
        $ui = hash_hmac($algo, hex2bin($salt_int), $data, 1);
        $result = $ui;
        for ($k = 1; $k < $i; $k++) {
            $ui = hash_hmac($algo, $ui, $data, 1);

            $result = $result ^ $ui;

//            echo  "bin2hex(u", $k + 1, "): " . bin2hex($ui).'<br>';
//            echo  "bin2hex(result", $k + 1, "): " . bin2hex($result).'<br>';
//            if ($k > 5) break;
        }
        return $result;
    }


    /**
     * @return mixed
     */
    private function getClientNonce()
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
    private function getSalt()
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
     * @return mixed
     */
    private function getHashAlg()
    {
        return $this->hashAlg;
    }

    /**
     * @return mixed
     */
    private function getIterationCount()
    {
        return $this->iterationCount;
    }

    /**
     * @return mixed
     */
    private function getServerNonce()
    {
        return $this->serverNonce;
    }
}