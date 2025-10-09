<?php
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/www/open-encrypt.com/html/error.log');
error_reporting(E_ALL);

include_once 'include/db_config.php';
include_once 'include/Database.php';
require_once 'include/utils.php';
$db = new Database($conn);

// ------------------ Handle form submission ------------------

$error_message = '';

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$valid_username = valid_username($username) && !username_exists($db, $username);
$valid_password = valid_password($password);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$valid_username) {
        $error_message = "<p class='error-message'>Invalid or duplicate username.</p>";
        error_log("Error: Invalid or duplicate username.");
    }

    if (!$valid_password) {
        $error_message = "<p class='error-message'>Invalid password.</p>";
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
            $error_message = "<p class='success-message'>Account created successfully!</p>";
            error_log("New account created successfully for " . htmlspecialchars($username));
            session_start();
            $_SESSION['user'] = $username;
            redirect("inbox.php");
        } else {
            $error_message = "<p class='error-message'>Failed to create account.</p>";
            error_log("Error: Failed to create account.");
        }
    }
}
?>

<html>
<head>
    <title>Open Encrypt - Create Account</title>
    <link rel="stylesheet" href="style/style.css">
</head>
<body>

<header>
    <h1><a href="index.html">Open Encrypt</a></h1>
    <h2>Status: Development (10/8/2025)</h2>
</header>

<hr>

<h2>Create Account</h2>

<div class="account-form">
    <form action="create_account.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" value="<?= htmlspecialchars($username) ?>" required>

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>

        <input type="submit" value="Create Account">
    </form>

    <p>Already have an account? 
        <a href="login.php" class="button-link">Login</a>
    </p>
</div>

<?php
if ($error_message !== '') {
    echo '<div class="message-box">' . $error_message . '</div>';
}
?>

</body>
</html>