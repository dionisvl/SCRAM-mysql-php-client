<?php

//use ScramParams;

/*
 * Паттерн "стратегия" для резолвинга метода аутентификации
 * (client side)
 */

use AuthEncryptors\OpensslHash;
use AuthEncryptors\PhpHash;


class AuthStrategyDispatcher
{
    public function resolveStrategy($data)
    {
        try {
            switch ($data['protocolVersion']) {
                case 'mysql':
                    $inst = new MySqlAuthStrategy();
                    $inst->setHashAlg($data['hashAlg']);
                    $inst->setHashCount($data['hashCount']);
                    switch ($data['encrypter']) {
                        case 'openssl':
                            $this->setEncrypter(new OpensslHash());
                            break;
                        case 'phphash':
                            $this->setEncrypter(new PhpHash());
                            break;
                        default:
                            throw new \RuntimeException('Error: Bad encrypter version: '. $data['encrypter']);
                    }
                    break;
                case 'scram':
                    $inst = new ScramAuthStrategy();
                    $inst->setHashAlg($data['hashAlg']);
                    $inst->setHashCount($data['hashCount']);
                    switch ($data['encrypter']) {
                        case 'openssl':
                            $this->setEncrypter(new OpensslHash());
                            break;
                        case 'phphash':
                            $this->setEncrypter(new PhpHash());
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
        } catch (Exception $e) {
            throw new \RuntimeException('Ошибка, нехватает полей от сервера: ',  $e->getMessage(), "\n");
        }
    }
}