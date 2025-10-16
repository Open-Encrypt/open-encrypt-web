<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../include/encryption.php';

class ApiTest extends TestCase
{
    public function testRustEncryptionRoundtrip()
    {
        $plaintext = "Hello Open Encrypt!";

        // Generate key pair using default method ("ring_lwe")
        $keys = generate_keys();
        var_dump($keys);
        $this->assertArrayHasKey('public_key', $keys);
        $this->assertArrayHasKey('secret_key', $keys);

        $publicKey = $keys['public_key'];
        $secretKey = $keys['secret_key'];

        // Encrypt message
        $ciphertext = encrypt_message($publicKey, $plaintext);
        $this->assertNotEmpty($ciphertext, "Ciphertext should not be empty");

        // Decrypt message
        $decrypted = decrypt_message($secretKey, $ciphertext);
        $this->assertEquals($plaintext, $decrypted, "Decrypted text should match original plaintext");
    }

    public function testModuleLweEncryptionRoundtrip()
    {
        $plaintext = "Test Module LWE";

        // Generate key pair using module-lwe
        $keys = generate_keys("module_lwe");
        var_dump($keys); // <-- add this
        $this->assertArrayHasKey('public_key', $keys);
        $this->assertArrayHasKey('secret_key', $keys);

        $publicKey = $keys['public_key'];
        $secretKey = $keys['secret_key'];

        // Encrypt message
        $ciphertext = encrypt_message($publicKey, $plaintext, "module_lwe");
        $this->assertNotEmpty($ciphertext, "Ciphertext should not be empty");

        // Decrypt message
        $decrypted = decrypt_message($secretKey, $ciphertext, "module_lwe");
        $this->assertEquals($plaintext, $decrypted, "Decrypted text should match original plaintext");
    }
}
