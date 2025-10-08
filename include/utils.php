<?php
// utility functions for user validation and token management

function redirect($url) {
    header('Location: ' . $url);
    die();
}

// generate a secure login token
function generate_token(): string {
    return bin2hex(random_bytes(16)); // 32 characters
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
function valid_message(string $message, int $max_len): bool {
    if (empty($message)) {
        return false;
    }
    if (!preg_match("/^[a-zA-Z0-9_ !?.:;~@#,()+=&$-]*$/", $message)) {
        return false;
    }
    if (strlen($message) > $max_len) {
        return false;
    }
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
