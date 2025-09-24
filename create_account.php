<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');

include_once 'include/db_config.php';
include_once 'include/Database.php';
$db = new Database($conn);

// ------------------ Helper functions ------------------

// validate username and ensure uniqueness
function validate_username(Database $db, string $username, int $max_len = 14): bool {
    if (empty($username)) return false;
    if (!preg_match("/^[a-zA-Z0-9_]*$/", $username)) return false;
    if (strlen($username) > $max_len) return false;

    // Check uniqueness in the database
    $count = $db->count("SELECT COUNT(*) FROM login_info WHERE username = ?", [$username], "s");
    return $count === 0;
}

// validate password
function validate_password(string $password, int $max_len = 24): bool {
    if (empty($password)) return false;
    if (!preg_match("/^[a-zA-Z0-9_-]*$/", $password)) return false;
    if (strlen($password) > $max_len) return false;
    return true;
}

// ------------------ Handle form submission ------------------

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$valid_username = validate_username($db, $username);
$valid_password = validate_password($password);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$valid_username) {
        echo "Invalid or duplicate username.<br>";
    }

    if (!$valid_password) {
        echo "Invalid password.<br>";
    }

    if ($valid_username && $valid_password) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $success = $db->execute(
            "INSERT INTO login_info (username, password) VALUES (?, ?)",
            [$username, $hashed_password],
            "ss"
        );

        if ($success) {
            echo "New account created successfully for " . htmlspecialchars($username) . ".<br>";
        } else {
            echo "Error: Failed to create account.<br>";
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
