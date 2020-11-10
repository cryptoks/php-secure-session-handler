<?php

interface IEncryptionDecryptionService {

    public function encrypt($value,$key);

    public function decrypt($value, $key);

}