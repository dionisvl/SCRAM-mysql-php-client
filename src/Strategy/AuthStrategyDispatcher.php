<?php

//use ScramParams;

/*
 * Паттерн "стратегия" для резолвинга метода аутентификации
 * (client side)
 */
namespace Bs\Sdk\Auth\Strategy;

use Bs\Sdk\Auth\Encryptors\OpensslHash;
use Bs\Sdk\Auth\Encryptors\PhpHash;
use Exception;


class AuthStrategyDispatcher
{
//    private $encryptor;
//
//    /**
//     * @param mixed $encryptor
//     */
//    public function setEncryptor($encryptor): void
//    {
//        $this->encryptor = $encryptor;
//    }


    public function resolveStrategy($data): IAuthStrategy
    {
//        try {
            switch ($data['protocolVersion']) {
                case 'MYSQL':
                    $inst = new MySqlAuthStrategy();
                    $inst->setHashAlg($data['hashAlg']);
                    $inst->setHashCount($data['hashCount']);
                    $inst->setServerNonce($data['nonce']);
                    switch ($data['encrypter']) {
                        case 'openssl':
                            $inst->setEncryptor(new OpensslHash());
                            break;
                        case 'phphash':
                            $inst->setEncryptor(new PhpHash());
                            break;
                        default:
                            throw new \RuntimeException('Error: Bad encrypter version: '. $data['encrypter']);
                    }
                    break;
                case 'SCRAM':
                    $inst = new ScramAuthStrategy();
                    $inst->setHashAlg($data['hashAlg']);
                    $inst->setHashCount($data['hashCount']);
                    $inst->setServerNonce($data['nonce']);
                    switch ($data['encrypter']) {
                        case 'openssl':
                            $inst->setEncrypter(new OpensslHash());
                            break;
                        case 'phphash':
                            $inst->setEncrypter(new PhpHash());
                            break;
                        default:
                            throw new \RuntimeException('Error: Bad encrypter version: '. $data['encrypter']);
                    }
                    break;
                case 'plaintext':
                    //возвращает только пароль в чистом виде , поэтому ничего делать не будем
                    $inst = new PlaintextAuthStrategy();
                    break;
                case '1.0':
                    throw new \Exception('todo: implement needed');
                default:
                    throw new \Exception('Error: Bad protocol version: '. $data['protocolVersion']);
            }

            return $inst;
//        } catch (Exception $e) {
//            throw new \RuntimeException('Ошибка, нехватает полей от сервера: ',  $e->getMessage(), "\n");
//        }
    }
}