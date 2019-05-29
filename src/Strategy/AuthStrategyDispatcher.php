<?php

namespace Bs\Sdk\Auth\Strategy;

/*
 * Паттерн "стратегия" для резолвинга метода аутентификации
 * (client side)
 */

use Exception;

class AuthStrategyDispatcher
{
    public function resolveStrategy($data): IAuthStrategy
    {
//        try {
            switch ($data['protocolVersion']) {
                case 'reducedScram':
                    $inst = new ReducedScramAuthStrategy();
                    $inst->setHashAlg($data['hashAlg']);

                    $inst->setServiceKey($data['serviceKey']);
                    $inst->setServiceName($data['serviceName']);
                    $inst->setTimestamp($data['timestamp']);
                    $inst->setSecureRandom($data['secureRandom']);
                    break;
                case 'MYSQL':
                    $inst = new MySqlAuthStrategy();
                    $inst->setHashAlg($data['hashAlg']);
                    $inst->setServerNonce($data['serverNonce']);
                    break;
                case 'SCRAM':
                    $inst = new ScramAuthStrategy();
                    $inst->setHashAlg($data['hashAlg']);
                    $inst->setiterationCount($data['iterationCount']);
                    $inst->setServerNonce($data['serverNonce']);
                    $inst->setSalt($data['salt']);
                    $inst->setClientNonce($data['clientNonce']);
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