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
error_log("decoded json data from POST: " . print_r($data, true));
$response['status'] = 'failure';
?>

<?php
// fetch the token from the database and verify it matches the given token
function verify_token(Database $db, string $username, string $token) {
    error_log("running verify_token for user: " . $username);
    try {
        // fetchOne returns the first column of the first row (or null if no row)
        $stored_token = $db->fetchOne(
            "SELECT token FROM login_info WHERE username = ?",
            [$username],
            "s"
        );

        if ($stored_token === null) {
            error_log("stored token is null for user: " . $username);
            return false;
        }

        return $stored_token['token'] === $token;
    } catch (Exception $e) {
        error_log("verify_token exception: " . $e->getMessage());
        return false;
    }
}
//decrypt a message using the secret key
function decrypt_message(string $secret_key, string $ciphertext, string $encryption_method="ring_lwe"){
    error_log("running decrypt_message with method: " . $encryption_method);
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
function encrypt_message(string $public_key, string $plaintext, string $encryption_method = "ring_lwe") {
    error_log("running encrypt_message with method: " . $encryption_method);
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
function valid_secret_key(string $secret_key, string $encryption_method = "ring_lwe") {
    error_log("running valid_secret_key with method: " . $encryption_method);
    // check if secret key is empty
    if (empty($secret_key)) {
        error_log("Error: " . "secret key is empty.");
        return false;
    }

    // check if it's a valid base64 string
    if (!preg_match("/^[A-Za-z0-9+\/]+={0,2}$/",$secret_key)) {
        error_log("Error: " . "secret key is not valid base64 string.");
        return false;
    }

    // optional: enforce max length depending on method
    if ($encryption_method === "ring_lwe" && strlen($secret_key) > 10936) {
        error_log("Error: " . "ring-lwe secret key is too long: " . strlen($secret_key));
        return false;
    }
    if ($encryption_method === "module_lwe" && strlen($secret_key) > 43704) {
        error_log("Error: " . "module-lwe secret key is too long: " . strlen($secret_key));
        return false;
    }

    return true;
}
// validate user input for public keys
function valid_public_key(string $public_key, string $encryption_method = "ring_lwe") {
    error_log("running valid_public_key with method: " . $encryption_method);
    // check if public key is empty
    if (empty($public_key)) {
        error_log("Error: " . "public key is empty.");
        return false;
    }

    // check if it's a valid base64 string
    if (!preg_match("/^[A-Za-z0-9+\/]+={0,2}$/",$public_key)) {
        error_log("Error: " . "public key is not a valid base64 string.");
        return false;
    }

    // optional: enforce max length depending on method
    if ($encryption_method === "ring_lwe" && strlen($public_key) > 21856) { // adjust size as needed
        error_log("Error: " . "ring-lwe public key exceeds maximum length: " . strlen($public_key));
        return false;
    }
    if ($encryption_method === "module_lwe" && strlen($public_key) > 393228) {
        error_log("Error: " . "module-lwe public key exceeds maximum length: " . strlen($public_key));
        return false;
    }

    return true;
}
// validate username input from form
function valid_username(string $username, int $max_len){
    if (empty($username)) {
        error_log("Error: " . "username is empty.");
        return false;
    }
    // To check that username only contains alphabets, numbers, and underscores 
    if (!preg_match("/^[a-zA-Z0-9_]*$/", $username)) {
        error_log("Error: " . "username contains invalid characters.");
        return false;
    }
    if (strlen($username) > $max_len) {
        error_log("Error: " . "username is too long: " . strlen($username));
        return false;
    }
    return true;
}
// validate message input from form
function valid_message($message,$max_len){
    if (empty($message)) {
        error_log("Error: " . "message is empty.");
        return false;
    }
    // To check that message only contains alphabets, numbers, underscores, spaces
    if (!preg_match("/^[a-zA-Z0-9_ !?.:;~@#,()+=&$-]*$/", $message)) {
        error_log("Error: " . "message contains invalid characters.");
        return false;
    }
    if (strlen($message) > $max_len) {
        error_log("Error: " . "message is too long: " . strlen($message));
        return false;
    }
    return true;
}
// Fetch messages for a given user
function get_messages(Database $db, string $username, string $secret_key, array &$response, string $encryption_method = "ring_lwe") {
    error_log("running get_messages for user: " . $username);

    // Initialize response arrays
    $response['from'] = [];
    $response['to'] = [];
    $response['messages'] = [];

    // Validate secret key
    $valid_secret_key = valid_secret_key($secret_key, $encryption_method);

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
// Retrieve the public key from the database for the given username
function get_public_key(Database $db, string $username, array &$response): ?string {
    error_log("running get_public_key for user: " . $username);
    try {
        if ($db->exists('public_keys', 'username', $username)) {
            $row = $db->fetchOne(
                "SELECT `public_key` FROM `public_keys` WHERE `username` = ?",
                [$username],
                "s"
            );
            $response['public_key'] = $row['public_key'];
            $response['status'] = "success";
            return $row['public_key'] ?? null;
        } else {
            error_log("No public key found for user: " . $username);
            $response['error'] = "No public key for $username";
            return null;
        }
    } catch (Exception $e) {
        $response['error'] = "Exception in get_public_key: " . $e->getMessage();
        error_log("Exception during get_public_key for username: $username: " . $e->getMessage());
        return null;
    }
}

// Define a function which generates public and private keys using the Rust binary
function generate_keys(array &$response, string $encryption_method = "ring_lwe") {
    error_log("running generate_keys with method: " . $encryption_method);
    $binary_path = "/var/www/open-encrypt.com/html/";
    $binary = $encryption_method === "ring_lwe" ? "ring-lwe-v0.1.8" : "module-lwe-v0.1.5";
    $command = escapeshellcmd($binary_path . $binary . " keygen");
    
    $json_string = shell_exec($command);
    try {
        $json_object = json_decode($json_string, true, 512, JSON_THROW_ON_ERROR);
    } catch (Exception $e) {
        $response['error'] = "Key generation failed: " . $e->getMessage();
        $response['status'] = "failure";
        error_log("Exception during get_public_key: " . $e->getMessage());
        return;
    }

    // set the response values for secret and public keys
    $response['secret_key'] = $json_object["secret"];
    $response['public_key'] = $json_object["public"];
    $response['status'] = "success";
}

function save_public_key(Database $db, string $username, string $public_key, array &$response) {
    error_log("running save_public_key for user: " . $username);
    try {
        // Check if they already have a public key stored
        if ($db->exists('public_keys', 'username', $username)) {
            // Update
            $ok = $db->execute(
                "UPDATE `public_keys` SET `public_key` = ? WHERE `username` = ?",
                [$public_key, $username],
                "ss"
            );
        } else {
            // Insert
            $ok = $db->execute(
                "INSERT INTO `public_keys` (`username`, `public_key`) VALUES (?, ?)",
                [$username, $public_key],
                "ss"
            );
        }

        $response['status'] = $ok ? "success" : "failure";
    } catch (Exception $e) {
        $response['status'] = "failure";
        $response['error'] = "Exception in save_public_key: " . $e->getMessage();
        error_log("Exception during save_public_key for username: $username: " . $e->getMessage());
    }
}

// Function for sending messages
function send_message(Database $db, string $from_username, string $to_username, string $message, array &$response, string $encryption_method = "ring_lwe") {
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
    if (empty($encrypted_message)) {
        $response['error'] = "Encryption failed: empty result.";
        return;
    }

    // Insert the message into the messages table
    try {
        $db->execute(
            "INSERT INTO `messages` (`from`, `to`, `message`, `method`) VALUES (?, ?, ?, ?)",
            [$from_username, $to_username, $encrypted_message, $encryption_method],
            "ssss"
        );
        $response['status'] = "success";
    } catch (Exception $e) {
        error_log("Exception during message insertion: " . $e->getMessage());
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
            error_log("begin getting messages for user: " . $username);
            $secret_key = $data['secret_key'];
            get_messages($db,$username,$secret_key,$response);
            error_log("finished getting messages for user: " . $username);
        }
        if($action == "get_public_key"){
            error_log("begin getting public key for user: " . $username);
            get_public_key($db,$username,$response);
            error_log("finished getting public key for user: " . $username);
        }
        if($action == "generate_keys"){
            error_log("begin generating keys for user: " . $username);
            generate_keys($response);
            error_log("finished generating keys for user: " . $username);
        }
        if($action == "save_public_key"){
            error_log("begin saving public key for user: " . $username);
            $public_key = $data['public_key'];
            save_public_key($db, $username,$public_key,$response);
            error_log("finished saving public key for user: " . $username);
        }
        if($action == "send_message"){
            error_log("begin sending message for user: " . $username);
            $to_username = $data['recipient'];
            $message = $data['message'];
            send_message($db,$username,$to_username,$message,$response);
            error_log("finished sending message for user: " . $username);
        }
    }
}
?>

<?php
echo json_encode($response);
?>