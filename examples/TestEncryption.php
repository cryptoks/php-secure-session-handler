<?php

include_once ("../src/interfaces/IEncryptionDecryptionService.php");
include_once ("../src/EncryptionDecryptionService.php");
include_once ("../src/SessionSecureHandler.php");

$EncryptDecryptService = new \Adirona\EncryptionDecryptionService\EncryptionDecryptionService();
$session = new \Adirona\SessionSecureHandler\SessionSecureHandler($EncryptDecryptService,null,[
    'session.save_path' => $_SERVER['DOCUMENT_ROOT'] . "/SessionHandler/examples/sessionsFolder/"
]);

$session->start();

##Documentation will be available soon