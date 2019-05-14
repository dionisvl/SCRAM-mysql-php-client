<?php


class PlaintextAuthStrategy extends AbstractAuthStrategy implements IAuthStrategy
{
    public function createClientProof($password)
    {
        return $password;
    }
}