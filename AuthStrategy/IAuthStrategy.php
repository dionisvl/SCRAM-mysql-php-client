<?php


interface IAuthStrategy
{
    function createClientProof($password);
}