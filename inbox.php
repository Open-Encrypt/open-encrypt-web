<?php
ini_set('display_errors', '1');
ini_set('display_startup_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', '/var/www/open-encrypt.com/html/error.log');
error_reporting(E_ALL);

require_once 'include/db_config.php';
require_once 'include/Database.php';
require_once 'include/utils.php';
require_once 'include/encryption.php';

session_start();

// If not logged in, redirect to home
if (!isset($_SESSION['user'])) {
    header("Location: index.html");
    exit();
}

// Optional: redirect immediately to send_message.php or view_messages.php
// header("Location: send_message.php");
// exit();
?>
<!DOCTYPE html>
<html>
<head>
    <title>Inbox | Open Encrypt</title>
</head>
<body>
<h1>Open Encrypt</h1>
<h2>Status: Development (10/8/2025)</h2>

<div>
    <a href="index.html">Home</a> |
    <a href="inbox.php">Inbox</a> |
    <a href="send_message.php">Send Message</a> |
    <a href="view_messages.php">View Messages</a> |
    <a href="key_management.php">Key Management</a> |
    <form method="post" style="display:inline; margin:0;">
        <input type="submit" name="logout" value="Logout" style="cursor:pointer;">
    </form>
</div>
<hr>

<p>Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?>.</p>
<p>This page is currently empty. Please use <a href="send_message.php">Send Message</a> or <a href="view_messages.php">View Messages</a>.</p>

<?php
if (array_key_exists('logout', $_POST)) {
    logout();
}
?>
</body>
</html>