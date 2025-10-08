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
    <title>Open Encrypt - View Messages</title>
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

<h2>View Messages</h2>
<h2>User: <?php echo htmlspecialchars($username); ?></h2>

<!-- View encrypted messages -->
<form method="post" style="margin-bottom:10px;">
    <input type="submit" name="view_messages" value="View Encrypted Messages" />
</form>

<!-- Decrypt messages -->
<form method="post" enctype="multipart/form-data">
    <label for="secret_key_file">Upload Secret Key File:</label>
    <input type="file" id="secret_key_file" name="secret_key_file" accept=".txt,.key" required><br>
    <input type="radio" id="ring_lwe" name="encryption_method" value="ring_lwe" checked>
    <label for="ring_lwe">ring-LWE</label>
    <input type="radio" id="module_lwe" name="encryption_method" value="module_lwe">
    <label for="module_lwe">module-LWE</label><br>
    <input type="submit" name="decrypt_messages" value="Decrypt Messages" />
</form>

<?php
// Handle viewing encrypted messages
if (isset($_POST['view_messages'])) {
    display_messages($db, $username);
}

// Handle decrypting messages
if (isset($_POST['decrypt_messages'], $_POST['encryption_method'])) {
    $encryption_method = $_POST['encryption_method'];

    if (!isset($_FILES['secret_key_file']) || $_FILES['secret_key_file']['error'] !== UPLOAD_ERR_OK) {
        echo "<p>Error: Secret key file is required.</p>";
        return;
    }

    $tmp_name = $_FILES['secret_key_file']['tmp_name'];
    $seckey_tempfile = make_tempfile('seckey_');

    if (!move_uploaded_file($tmp_name, $seckey_tempfile) && !copy($tmp_name, $seckey_tempfile)) {
        echo "<p>Error: Failed to store uploaded secret key.</p>";
        return;
    }

    $secret_key_contents = trim(file_get_contents($seckey_tempfile));
    if ($secret_key_contents === false || !valid_secret_key($secret_key_contents, $encryption_method)) {
        echo "<p>Error: Invalid secret key.</p>";
        return;
    }

    display_messages($db, $username, $seckey_tempfile, $encryption_method);

    if (file_exists($seckey_tempfile)) @unlink($seckey_tempfile);
}
?>

</body>
</html>