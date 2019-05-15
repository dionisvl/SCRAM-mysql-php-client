<?php

namespace Bs\Sdk\Auth\Strategy;

interface IAuthStrategy
{
    function createClientProof($password);
}