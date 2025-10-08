<?php

//define a function which generates public and private keys
function generate_keys($encryption_method = "ring_lwe"){
    $binary_path = "/var/www/open-encrypt.com/html/bin/";
    $command = escapeshellcmd($binary_path . ($encryption_method == "ring_lwe" ? "ring-lwe-v0.1.8" : "module-lwe-v0.1.5") . " keygen");
    $json_string = shell_exec($command);
    try{
        $json_object = json_decode($json_string, true, 512, JSON_THROW_ON_ERROR);
    }
    catch(Exception $e){
        print $e;
    }
    return $json_object;
}

// Encrypt a message using the given public key
function encrypt_message($public_key, $plaintext, $encryption_method = "ring_lwe") {
    $binary_path = "/var/www/open-encrypt.com/html/bin/";
    $binary = ($encryption_method == "ring_lwe" ? "ring-lwe-v0.1.8" : "module-lwe-v0.1.5");
    $binary_full = $binary_path . $binary;

    if ($encryption_method == "ring_lwe") {
        // Inline key works fine for ring-lwe
        $command = escapeshellcmd(
            $binary_full 
            . " encrypt "
            . "--pubkey " 
            . escapeshellarg(trim($public_key))
            . " " 
            . escapeshellarg(trim($plaintext))
        ) . " 2>&1"; // capture stderr
    } else {
        // Write public key to a temp file for module-lwe
        $tmp_pubkey_file = tempnam(sys_get_temp_dir(), "pubkey_");
        file_put_contents($tmp_pubkey_file, trim($public_key));

        $command = escapeshellcmd(
            $binary_full 
            . " encrypt "
            . "--pubkey-file " 
            . escapeshellarg($tmp_pubkey_file)
            . " " 
            . escapeshellarg(trim($plaintext))
        ) . " 2>&1"; // capture stderr
    }

    $encrypted_string = shell_exec($command);

    // Optionally clean up temp file
    if (isset($tmp_pubkey_file) && file_exists($tmp_pubkey_file)) {
        unlink($tmp_pubkey_file);
    }

    return $encrypted_string;
}

//decrypt a message using the secret key
function decrypt_message($secret_key,$ciphertext,$encryption_method="ring_lwe"){
    $binary_path = "/var/www/open-encrypt.com/html/bin/";
    $command = escapeshellcmd(
        $binary_path 
        . ($encryption_method == "ring_lwe" ? "ring-lwe-v0.1.8" : "module-lwe-v0.1.5") 
        . " decrypt "
        . "--secret "
        . escapeshellarg(trim($secret_key)) 
        . " " 
        . escapeshellarg(trim($ciphertext))
    ) . " 2>&1";
    $decrypted_string = shell_exec($command);
    return $decrypted_string;
}

// Decrypt using secret key and ciphertext files
function run_decrypt_with_files(string $seckey_file, string $ciphertext_file, string $encryption_method) : string {
    $binary_path = "/var/www/open-encrypt.com/html/bin/";
    $binary = ($encryption_method === "ring_lwe")
        ? "ring-lwe-v0.1.8"
        : "module-lwe-v0.1.5";

    $cmd = $binary_path . $binary
        . " decrypt --secret-file " . escapeshellarg($seckey_file)
        . " --ciphertext-file " . escapeshellarg($ciphertext_file)
        . " 2>&1";

    $output = shell_exec($cmd);
    return $output === null ? "" : $output;
}

?>