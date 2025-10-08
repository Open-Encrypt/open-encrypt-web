<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');

// form a connection to the SQL database
include_once 'include/db_config.php';
include_once 'include/Database.php';
include_once 'include/utils.php';
$db = new Database($conn);

session_start();

function redirect($url) {
    header('Location: ' . $url);
    die();
}

// redirect if user is already logged in
if (isset($_SESSION['user'])) {
    redirect("inbox.php");
}

// check if username exists in login_info
function username_exists(Database $db, string $username): bool {
    $count = $db->count("SELECT COUNT(*) FROM login_info WHERE username = ?", [$username], "s");
    return $count > 0;
}

// store login token in database
function store_token(Database $db, string $username, string $token): bool {
    return $db->execute("UPDATE login_info SET token = ? WHERE username = ?", [$token, $username], "ss");
}

// ------------------ Process form submission ------------------

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$valid_username = validate_username($username) && username_exists($db, $username);
$valid_password = validate_password($password);

if ($valid_username && $valid_password) {
    $row = $db->fetchOne("SELECT password FROM login_info WHERE username = ?", [$username], "s");

    if ($row && password_verify($password, $row['password'])) {
        $login_token = generate_token();
        store_token($db, $username, $login_token);

        $_SESSION['user'] = $username;
        redirect("inbox.php");
    } else {
        echo "Error: Incorrect password or user not found.<br>";
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    echo "Invalid username or password.<br>";
}

?>
<html>
<head>
    <title>Open Encrypt</title>
</head>
<body>
    <h1>Under construction.</h1>

    <a href="index.html">Home</a>
    <a href="create_account.php">Create Account</a>

    <form action="login.php" method="POST">
        Username: <input type="text" name="username" value="<?= htmlspecialchars($username) ?>"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>

    <?php
    if (isset($_SESSION['user'])) {
        echo "Logged in user: " . htmlspecialchars($_SESSION['user']);
    }
    ?>
</body>
</html>
