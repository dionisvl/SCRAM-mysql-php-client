<?php

namespace Bs\Sdk\Auth\Strategy;


class PlaintextAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{
    public function createClientProof($password)
    {
        return $password;
    }
}