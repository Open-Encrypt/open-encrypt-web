<?php
ini_set('display_errors', 0);  // Display errors in the browser (for debugging purposes)
ini_set('log_errors', 1);      // Enable error logging
ini_set('error_log', '/var/www/open-encrypt.com/html/error.log');  // Absolute path to the error log file
error_reporting(E_ALL);         // Report all types of errors

// form a connection to the SQL database
include_once 'include/db_config.php';
include_once 'include/Database.php';
require_once 'include/utils.php';
$db = new Database($conn);

session_start();

// redirect if user is already logged in
if (isset($_SESSION['user'])) {
    redirect("inbox.php");
}

// ------------------ Process form submission ------------------

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$valid_username = valid_username($username) && username_exists($db, $username);
$valid_password = valid_password($password);

if ($valid_username && $valid_password) {
    $row = $db->fetchOne("SELECT password FROM login_info WHERE username = ?", [$username], "s");

    if ($row && password_verify($password, $row['password'])) {
        $login_token = generate_token();
        store_token($db, $username, $login_token);

        $_SESSION['user'] = $username;
        redirect("inbox.php");
    } else {
        error_log("Error: Incorrect password or user not found.");
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    error_log("Invalid username or password.");
}

?>
<html>
<head>
    <title>Open Encrypt</title>
</head>
<body>
    <h1>Open Encrypt</h1>
    <h2>Status: Development (10/8/2025)</h2>

    <a href="index.html">Home</a>
    <a href="create_account.php">Create Account</a>

    <form action="login.php" method="POST">
        Username: <input type="text" name="username" value="<?= htmlspecialchars($username) ?>"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>

    <?php
    if (isset($_SESSION['user'])) {
        error_log("Logged in user: " . htmlspecialchars($_SESSION['user']));
    }
    ?>
</body>
</html>
