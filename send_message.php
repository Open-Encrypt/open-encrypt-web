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

// Send message logic
if (isset($_POST['to'], $_POST['message'])) {
    $to_username = $_POST['to'];
    $message = $_POST['message'];

    if (!valid_username($to_username, 14)) { echo "<p>Error: Invalid recipient.</p>"; return; }
    if (!valid_message($message, 240)) { echo "<p>Error: Invalid message.</p>"; return; }

    $recipient = $db->fetchOne("SELECT username FROM login_info WHERE username = ?", [$to_username], "s");
    if ($recipient === null) { echo "<p>Error: Recipient does not exist.</p>"; return; }

    $pub_row = $db->fetchOne("SELECT public_key, method FROM public_keys WHERE username = ?", [$to_username], "s");
    if ($pub_row === null || !valid_public_key($pub_row['public_key'], $pub_row['method'])) {
        echo "<p>Error: Recipient's public key is invalid or missing.</p>"; return;
    }

    $encrypted = encrypt_message($pub_row['public_key'], $message, $pub_row['method']);
    $success = $db->execute(
        "INSERT INTO messages (`from`,`to`,`message`,`method`) VALUES (?,?,?,?)",
        [$username, $to_username, $encrypted, $pub_row['method']],
        "ssss"
    );

    echo $success ? "<p>Message sent successfully using {$pub_row['method']}.</p>" :
                    "<p>Error sending message.</p>";
}
?>

<html>
<head>
    <title>Open Encrypt - Send Message</title>
</head>
<body>
<h1>Open Encrypt</h1>

<div>
    <a href="index.html">Home</a> |
    <a href="send_message.php">Send Message</a> |
    <a href="inbox.php">Inbox</a> |
    <a href="view_messages.php">View Messages</a> |
    <a href="key_management.php">Key Management</a> |
    <form method="post" style="display:inline; margin:0;">
        <input type="submit" name="logout" value="Logout" style="cursor:pointer;">
    </form>
</div>
<hr>

<h2>Welcome, <?php echo htmlspecialchars($username); ?></h2>

<!-- Send Message Form -->
<form method="post" style="max-width:400px; padding:5px; border:1px solid #000; background:#fff;">
    <label for="to">To:</label><br>
    <input type="text" id="to" name="to" style="width:100%; margin-bottom:5px; border:1px solid #000; padding:2px;"><br>

    <label for="message">Message:</label><br>
    <input type="text" id="message" name="message" style="width:100%; margin-bottom:5px; border:1px solid #000; padding:2px;"><br>

    <input type="submit" value="Send" style="background:#000; color:#fff; border:none; padding:5px 8px; cursor:pointer;">
</form>

</body>
</html>
