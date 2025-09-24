<?php
ini_set('display_errors', 0);  // Display errors in the browser (for debugging purposes)
ini_set('log_errors', 1);      // Enable error logging
ini_set('error_log', '/var/www/open-encrypt.com/html/error.log');  // Absolute path to the error log file
error_reporting(E_ALL);         // Report all types of errors
// form a connection to the SQL database
include_once 'include/db_config.php';
include_once 'include/Database.php';
$db = new Database($conn);
header('Content-Type: application/json'); // Set the content type to JSON
$response = array();
// Get the raw POST data (JSON input)
$data = json_decode(file_get_contents('php://input'), true);
$response['status'] = 'failure';
?>

<?php
// fetch the token from the database and verify it matches the given token
function verify_token($db, $username, $token) {
    try {
        // fetchOne returns the first column of the first row (or null if no row)
        $stored_token = $db->fetchOne(
            "SELECT token FROM login_info WHERE username = ?",
            [$username],
            "s"
        );

        if ($stored_token === null) {
            return false; // username not found
        }

        return $stored_token === $token;
    } catch (Exception $e) {
        // you can log the exception if needed
        error_log("verify_token exception: " . $e->getMessage());
        return false;
    }
}
//decrypt a message using the secret key
function decrypt_message($secret_key,$ciphertext,$encryption_method="ring_lwe"){
    $binary_path = "/var/www/open-encrypt.com/html/";
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
// Encrypt a message using the given public key
function encrypt_message($public_key, $plaintext, $encryption_method = "ring_lwe") {
    $binary_path = "/var/www/open-encrypt.com/html/";
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
// validate user input for secret keys
function valid_secret_key($secret_key, $encryption_method = "ring_lwe") {
    // check if secret key is empty
    if (empty($secret_key)) {
        return false;
    }

    // check if it's a valid base64 string
    if (!preg_match("/^[A-Za-z0-9+\/]+={0,2}$/",$secret_key)) {
        echo "Error: " . "secret key is not valid base64 string.";
        return false;
    }

    // optional: enforce max length depending on method
    if ($encryption_method === "ring_lwe" && strlen($secret_key) > 10936) {
        return false;
    }
    if ($encryption_method === "module_lwe" && strlen($secret_key) > 43704) {
        return false;
    }

    return true;
}
// validate user input for public keys
function valid_public_key($public_key, $encryption_method = "ring_lwe") {
    // check if public key is empty
    if (empty($public_key)) {
        echo "Error: " . "public key is empty.";
        return false;
    }

    // check if it's a valid base64 string
    if (!preg_match("/^[A-Za-z0-9+\/]+={0,2}$/",$public_key)) {
        echo "Error: " . "public key is not valid base64 string.";
        return false;
    }

    // optional: enforce max length depending on method
    if ($encryption_method === "ring_lwe" && strlen($public_key) > 21856) { // adjust size as needed
        echo "Error: " . "public key exceeds maximum length for ring_lwe.";
        return false;
    }
    if ($encryption_method === "module_lwe" && strlen($public_key) > 393228) {
        echo "Error: " . "public key exceeds maximum length for module_lwe.";
        return false;
    }

    return true;
}
// validate username input from form
function valid_username($username,$max_len){
    if (empty($username)) {
        return false;
    }
    // To check that username only contains alphabets, numbers, and underscores 
    if (!preg_match("/^[a-zA-Z0-9_]*$/", $username)) {
        return false;
    }
    if (strlen($username) > $max_len) {
        return false;
    }
    return true;
}
// validate message input from form
function valid_message($message,$max_len){
    if (empty($message)) {
        return false;
    }
    // To check that message only contains alphabets, numbers, underscores, spaces
    if (!preg_match("/^[a-zA-Z0-9_ !?.:;~@#,()+=&$]*$/", $message)) {
        return false;
    }
    if (strlen($message) > $max_len) {
        return false;
    }
    return true;
}
// Fetch messages for a given user
function get_messages($db, $username, $secret_key, &$response, $encryption_method = "ring_lwe") {
    $response['from'] = [];
    $response['to'] = [];
    $response['messages'] = [];

    $valid_secret_key = valid_secret_key($secret_key);

    try {
        // fetchAll returns an array of associative arrays
        $messages = $db->fetchAll(
            "SELECT `from`, `to`, `message` FROM messages WHERE `to` = ? ORDER BY `id` ASC",
            [$username],
            "s"
        );

        if (empty($messages)) {
            $response['status'] = "success";
            return; // no messages
        }

        $response['status'] = "success";

        foreach ($messages as $row) {
            $response['from'][] = $row['from'];
            $response['to'][] = $row['to'];

            if ($valid_secret_key) {
                // decrypt using Rust binary and base64-encoded key
                $decrypted = decrypt_message($secret_key, $row['message'], $encryption_method);
                $response['messages'][] = $decrypted;
            } else {
                // leave message encrypted
                $response['messages'][] = $row['message'];
            }
        }
    } catch (Exception $e) {
        $response['status'] = "failure";
        $response['error'] = "Exception: " . $e->getMessage();
        error_log("get_messages exception: " . $e->getMessage());
    }
}
// function to check whether a username exists in a given table
function username_exists($db, $username, $table, &$response) {
    try {
        $count = $db->fetchOne(
            "SELECT COUNT(*) FROM `$table` WHERE `username` = ?",
            [$username],
            "s"
        );

        return $count > 0;
    } catch (Exception $e) {
        $response['error'] = "Exception: " . $e->getMessage();
        return false;
    }
}
// Retrieve the public key from the database for the given username
function get_public_key($db, $username, &$response) {
    try {
        if ($db->exists('public_keys', 'username', $username)) {
            $row = $db->fetchRow(
                "SELECT `public_key` FROM `public_keys` WHERE `username` = ?",
                [$username],
                "s"
            );
            return $row['public_key'] ?? null;
        } else {
            $response['error'] = "Username does not exist in public_keys table.";
            return null;
        }
    } catch (Exception $e) {
        $response['error'] = "Database exception: " . $e->getMessage();
        return null;
    }
}
// Define a function which generates public and private keys using the Rust binary
function generate_keys(&$response, $encryption_method = "ring_lwe") {
    $binary_path = "/var/www/open-encrypt.com/html/";
    $binary = $encryption_method === "ring_lwe" ? "ring-lwe-v0.1.8" : "module-lwe-v0.1.5";
    $command = escapeshellcmd($binary_path . $binary . " keygen");
    
    $json_string = shell_exec($command);
    try {
        $json_object = json_decode($json_string, true, 512, JSON_THROW_ON_ERROR);
    } catch (Exception $e) {
        $response['error'] = "Key generation failed: " . $e->getMessage();
        $response['status'] = "failure";
        return;
    }

    // set the response values for secret and public keys
    $response['secret_key'] = $json_object["secret"];
    $response['public_key'] = $json_object["public"];
    $response['status'] = "success";
}

// Function to store public key in the database using the Database class
function save_public_key($db, $username, $public_key, &$response) {
    try {
        if (!$db->exists('public_keys', 'username', $username)) {
            // Insert new public key
            $db->execute(
                "INSERT INTO public_keys (username, public_key, method) VALUES (?, ?, ?)",
                [$username, $public_key, $encryption_method],
                "sss"
            );
            $response['status'] = "success";
            error_log("Public key inserted successfully for username: $username");
        } else {
            // Update existing public key
            $db->execute(
                "UPDATE public_keys SET public_key = ?, method = ? WHERE username = ?",
                [$public_key, $encryption_method, $username],
                "sss"
            );
            $response['status'] = "success";
            error_log("Public key updated successfully for username: $username");
        }
    } catch (Exception $e) {
        $response['status'] = "failure";
        $response['error'] = "Database error: " . $e->getMessage();
        error_log("Exception during save_public_key for username: $username: " . $e->getMessage());
    }
}

// Function for sending messages
function send_message($db, $from_username, $to_username, $message, &$response, $encryption_method = "ring_lwe") {
    // Validate recipient and message
    if (!valid_username($to_username, 14)) {
        $response['error'] = "Error: Invalid recipient.";
        return;
    }
    if (!valid_message($message, 240)) {
        $response['error'] = "Error: Invalid message.";
        return;
    }

    // Check if recipient exists
    if (!$db->exists('login_info', 'username', $to_username)) {
        $response['error'] = "Error: Recipient username does not exist.";
        return;
    }

    // Fetch recipient public key
    $public_key = get_public_key($db, $to_username, $response);
    if (empty($public_key)) {
        $response['error'] = "Error: Could not retrieve recipient's public key.";
        return;
    }

    // Encrypt the message using Rust binary
    $encrypted_message = encrypt_message($public_key, $message, $encryption_method);

    // Insert the message into the messages table
    try {
        $db->execute(
            "INSERT INTO `messages` (`from`, `to`, `message`, `method`) VALUES (?, ?, ?, ?)",
            [$from_username, $to_username, $encrypted_message, $encryption_method],
            "ssss"
        );
        $response['status'] = "success";
    } catch (Exception $e) {
        $response['error'] = "Database exception: " . $e->getMessage();
    }
}

?>

<?php
//check action variable and decide which SQL query to run
if(isset($data['username']) && isset($data['token']) && isset($data['action'])){
    $username = $data['username'];
    $token = $data['token'];
    $action = $data['action'];

    if(verify_token($db, $username, $token)){
        if($action == "get_messages"){
            $secret_key = $data['secret_key'];
            get_messages($db,$username,$secret_key,$response);
        }
        if($action == "get_public_key"){
            get_public_key($db,$username,$response);
        }
        if($action == "generate_keys"){
            generate_keys($response);
        }
        if($action == "save_public_key"){
            $public_key = $data['public_key'];
            save_public_key($db, $username,$public_key,$response);
        }
        if($action == "send_message"){
            $to_username = $data['recipient'];
            $message = $data['message'];
            send_message($db,$username,$to_username,$message,$response);
        }
    }
}
?>

<?php
echo json_encode($response);
?>