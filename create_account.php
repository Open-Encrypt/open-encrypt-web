<?php
ini_set('display_errors', 0);  // Display errors in the browser (for debugging purposes)
ini_set('log_errors', 1);      // Enable error logging
ini_set('error_log', '/var/www/open-encrypt.com/html/error.log');  // Absolute path to the error log file
error_reporting(E_ALL);         // Report all types of errors

include_once 'include/db_config.php';
include_once 'include/Database.php';
require_once 'include/utils.php';
$db = new Database($conn);

// ------------------ Handle form submission ------------------

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$valid_username = valid_username($username) && !username_exists($db, $username);
$valid_password = valid_password($password);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$valid_username) {
        error_log("Error: Invalid or duplicate username.");
    }

    if (!$valid_password) {
        error_log("Error: Invalid password.");
    }

    if ($valid_username && $valid_password) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $success = $db->execute(
            "INSERT INTO login_info (username, password) VALUES (?, ?)",
            [$username, $hashed_password],
            "ss"
        );

        if ($success) {
            error_log("New account created successfully for " . htmlspecialchars($username));
        } else {
            error_log("Error: Failed to create account.");
        }
    }
}
?>

<html>
<head>
    <title>Open Encrypt</title>
</head>
<body>
    <h1>Under construction.</h1>

    <a href="index.html">Home</a>
    <a href="login.php">Login</a>

    <form action="create_account.php" method="POST">
        Username: <input type="text" name="username" value="<?= htmlspecialchars($username) ?>"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Create account">
    </form>
</body>
</html>
