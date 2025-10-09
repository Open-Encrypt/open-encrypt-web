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
$db = new Database($conn);

// Handle logout
if (isset($_POST['logout'])) logout();

// Ensure user is logged in
if (!isset($_SESSION['user'])) redirect("login.php");
$username = $_SESSION['user'];

?>

<html>
<head>
    <title>Open Encrypt - Send Message</title>
</head>
<body>
<h1><a href="index.html">Open Encrypt</a></h1>
<h2>Status: Development (10/8/2025)</h2>

<div>
    <a href="inbox.php">Home</a> |
    <a href="send_message.php">Send Message</a> |
    <a href="view_messages.php">View Messages</a> |
    <a href="key_management.php">Key Management</a> |
    <form method="post" style="display:inline; margin:0;">
        <input type="submit" name="logout" value="Logout" style="cursor:pointer;">
    </form>
</div>
<hr>

<h2>Send Message: <?php echo htmlspecialchars($username); ?></h2>

<!-- Send Message Form -->
<form method="post" style="max-width:400px; padding:5px; border:1px solid #000; background:#fff;">
    <label for="to">To:</label><br>
    <input type="text" id="to" name="to" style="width:100%; margin-bottom:5px; border:1px solid #000; padding:2px;"><br>

    <label for="message">Message:</label><br>
    <input type="text" id="message" name="message" style="width:100%; margin-bottom:5px; border:1px solid #000; padding:2px;"><br>

    <input type="submit" value="Send" style="background:#000; color:#fff; border:none; padding:5px 8px; cursor:pointer;">
</form>

<?php
if (isset($_POST['to'], $_POST['message'])) {
    $to_username = $_POST['to'];
    $message = $_POST['message'];
    $result = send_message($db, $username, $to_username, $message);
    echo "<p>" . htmlspecialchars($result['message']) . "</p>";
}
?>

</body>
</html>
