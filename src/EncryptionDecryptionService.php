<?php

namespace Adirona\EncryptionDecryptionService;

class EncryptionDecryptionService implements \IEncryptionDecryptionService
{

    public function encrypt($value, $key)
    {
        $nonce = random_bytes(
            SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
        );

        $cipher = base64_encode(
            $nonce .
            sodium_crypto_secretbox(
                $value,
                $nonce,
                $key
            )
        );
        sodium_memzero($message);
        sodium_memzero($key);
        return $cipher;
    }

    public function decrypt($value, $key)
    {
        $decoded = base64_decode($value);
        if ($decoded === false) {
            throw new Exception('Scream bloody murder, the encoding failed');
        }
        if (mb_strlen($decoded, '8bit') < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) {
            throw new Exception('Scream bloody murder, the message was truncated');
        }
        $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');

        $ciphertext = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

        $plain = sodium_crypto_secretbox_open(
            $ciphertext,
            $nonce,
            $key
        );
        if ($plain === false) {
            throw new Exception('the message was tampered with in transit');
        }
        sodium_memzero($ciphertext);
        sodium_memzero($key);
        return $plain;
    }
}