<?php
// utility functions for user validation and token management

function redirect($url) {
    header('Location: ' . $url);
    die();
}

//define a function which logs out the user
function logout(){
    // Unset all of the session variables.
    $_SESSION = array();

    // If it's desired to kill the session, also delete the session cookie.
    // Note: This will destroy the session, and not just the session data!
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
                
    // Finally, destroy the session.
    session_destroy();
    redirect("login.php");
}

// create a temporary file and return its name
function make_tempfile($prefix = 'oe_') {
    $tmp = sys_get_temp_dir();
    $name = tempnam($tmp, $prefix);
    if ($name === false) {
        throw new Exception("Unable to create temp file");
    }
    return $name;
}

// generate a secure login token
function generate_token(): string {
    return bin2hex(random_bytes(16)); // 32 characters
}

// fetch the public key for a given username
function fetch_public_key(Database $db, string $username): ?string {
    if (!username_exists($db, $username, "public_keys")) {
        return null;
    }

    $row = $db->fetchOne(
        "SELECT public_key FROM public_keys WHERE username = ?",
        [$username],
        "s"
    );

    return $row['public_key'] ?? null;
}

// Fetch encryption method for a username
function fetch_encryption_method(Database $db, string $username): ?string {
    if (!username_exists($db, $username, "public_keys")) {
        return null;
    }

    $row = $db->fetchOne(
        "SELECT method FROM public_keys WHERE username = ?",
        [$username],
        "s"
    );

    return $row['method'] ?? null;
}

// Check whether a username exists in the given table
function username_exists(Database $db, string $username, string $table = "login_info"): bool {
    $allowed_tables = ["login_info", "public_keys"];
    if (!in_array($table, $allowed_tables)) {
        throw new Exception("Invalid table name");
    }
    $query = "SELECT COUNT(*) FROM `$table` WHERE username = ?";
    $count = $db->count($query, [$username], "s");
    return $count > 0;
}

// store login token in database
function store_token(Database $db, string $username, string $token): bool {
    return $db->execute("UPDATE login_info SET token = ? WHERE username = ?", [$token, $username], "ss");
}

/**
 * Validate a username.
 * Rules:
 *  - Non-empty
 *  - Only letters, numbers, underscores
 *  - Not longer than $max_len
 */
function valid_username(string $username, int $max_len = 14): bool {
    if (empty($username)) {
        return false;
    }
    if (!preg_match("/^[a-zA-Z0-9_]*$/", $username)) {
        return false;
    }
    if (strlen($username) > $max_len) {
        return false;
    }
    return true;
}

/**
 * Validate a password.
 * Rules:
 * - Non-empty
 * - Only letters, numbers, underscores, hyphens
 * - Not longer than $max_len
 */
function valid_password(string $password, int $max_len = 24): bool {
    if (empty($password)) return false;
    if (!preg_match("/^[a-zA-Z0-9_-]*$/", $password)) return false;
    if (strlen($password) > $max_len) return false;
    return true;
}

/**
 * Validate a message.
 * Rules:
 *  - Non-empty
 *  - Only letters, numbers, underscores, spaces, and common punctuation
 *  - Not longer than $max_len
 */
function valid_message(string $message, int $max_len = 240): bool {
    if (empty($message)) return false;
    if (strlen($message) > $max_len) return false;
    // Allow all printable characters except control characters
    if (preg_match('/[[:cntrl:]&&[^\r\n\t]]/', $message)) return false;
    return true;
}

/**
 * Validate a secret key.
 * Rules:
 *  - Non-empty
 *  - Base64 format
 *  - Optional length restrictions depending on encryption method
 */
function valid_secret_key(string $secret_key, string $encryption_method = "ring_lwe"): bool {
    if (empty($secret_key)) {
        return false;
    }
    if (!preg_match("/^[A-Za-z0-9+\/]+={0,2}$/", $secret_key)) {
        return false;
    }
    if ($encryption_method === "ring_lwe" && strlen($secret_key) > 10936) {
        return false;
    }
    if ($encryption_method === "module_lwe" && strlen($secret_key) > 43704) {
        return false;
    }
    return true;
}

/**
 * Validate a public key.
 * Rules:
 *  - Non-empty
 *  - Base64 format
 *  - Optional length restrictions depending on encryption method
 */
function valid_public_key(string $public_key, string $encryption_method = "ring_lwe"): bool {
    if (empty($public_key)) {
        return false;
    }
    if (!preg_match("/^[A-Za-z0-9+\/]+={0,2}$/", $public_key)) {
        return false;
    }
    if ($encryption_method === "ring_lwe" && strlen($public_key) > 21856) {
        return false;
    }
    if ($encryption_method === "module_lwe" && strlen($public_key) > 393228) {
        return false;
    }
    return true;
}

// display messages for a user, optionally decrypting them if a secret key file is provided
function display_messages(Database $db, string $username, ?string $seckey_tempfile = null, ?string $encryption_method = null) {
    try {
        // now also select the timestamp
        $messages = $db->fetchAll(
            "SELECT `id`,`from`,`to`,`message`,`method`,`timestamp` 
             FROM `messages` 
             WHERE `to` = ? 
             ORDER BY `id` DESC",
             [$username],
             "s"
        );

        if (empty($messages)) {
            echo "<p>No messages found.</p>";
            return;
        }

        echo $seckey_tempfile ?
            "<p>Retrieved messages successfully... Decrypting messages...</p>" :
            "<p>Retrieved messages successfully.</p>";

        foreach ($messages as $row) {
            echo "<p>[id=" . htmlspecialchars($row['id']) . "] ";
            echo htmlspecialchars($row['from']) . " --> " . htmlspecialchars($row['to']);
            if (!$seckey_tempfile) echo " (" . htmlspecialchars($row['method']) . ")";
            
            // include timestamp if available
            if (!empty($row['timestamp'])) {
                $dt = new DateTime($row['timestamp'], new DateTimeZone('UTC'));
                $dt->setTimezone(new DateTimeZone('America/New_York'));
                $formatted_time = $dt->format('Y-m-d H:i:s');
                echo " <em>[" . htmlspecialchars($formatted_time) . " EST]</em>";
            }

            echo ": ";

            if ($seckey_tempfile && $encryption_method) {
                // Only decrypt messages that match encryption method
                if ($row['method'] !== $encryption_method) {
                    echo "[different encryption method]</p>";
                    continue;
                }

                $ct_tempfile = make_tempfile('ct_');
                file_put_contents($ct_tempfile, $row['message']);
                $out = run_decrypt_with_files($seckey_tempfile, $ct_tempfile, $encryption_method);
                echo htmlspecialchars($out) . "</p>";
                @unlink($ct_tempfile);
            } else {
                echo '<div style="display:inline-block; max-height:300px; overflow-y:auto; padding:5px; border:1px solid #ccc; background:#f9f9f9; font-family:monospace; white-space:pre;">';
                echo chunk_split(htmlspecialchars($row['message']), 64, "\n");
                echo '</div></p>';
            }
        }
    } catch (Exception $e) {
        echo "<p>Error fetching messages: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
}

// send an encrypted message from one user to another
function send_message(Database $db, string $username, string $to_username, string $message): array {
    // Will return: ['success' => bool, 'message' => string]

    if (!valid_username($to_username, 14)) {
        error_log("Error: Invalid recipient username '$to_username' by '$username'");
        return ['success' => false, 'message' => "Invalid recipient username."];
    }

    if (!valid_message($message, 240)) { // allow long messages
        error_log("Error: Invalid message content by '$username'");
        return ['success' => false, 'message' => "Invalid message content."];
    }

    $recipient = $db->fetchOne(
        "SELECT username FROM login_info WHERE username = ?",
        [$to_username],
        "s"
    );
    if ($recipient === null) {
        error_log("Error: Non-existent recipient '$to_username' by '$username'");
        return ['success' => false, 'message' => "Recipient does not exist."];
    }

    $pub_row = $db->fetchOne(
        "SELECT public_key, method FROM public_keys WHERE username = ?",
        [$to_username],
        "s"
    );
    if ($pub_row === null || !valid_public_key($pub_row['public_key'], $pub_row['method'])) {
        error_log("Error: Invalid/missing public key for '$to_username' (sent by '$username')");
        return ['success' => false, 'message' => "Recipient’s public key is invalid or missing."];
    }

    $encrypted = encrypt_message($pub_row['public_key'], $message, $pub_row['method']);
    $success = $db->execute(
        "INSERT INTO messages (`from`,`to`,`message`,`method`) VALUES (?,?,?,?)",
        [$username, $to_username, $encrypted, $pub_row['method']],
        "ssss"
    );

    if (!$success) {
        error_log("Database insert failed for message from '$username' to '$to_username'");
        return ['success' => false, 'message' => "Database error when storing message."];
    }

    return ['success' => true, 'message' => "Message sent successfully using {$pub_row['method']}."];
}

?>