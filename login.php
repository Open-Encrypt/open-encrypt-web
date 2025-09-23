<?php
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
    // form a connection to the SQL database
    include_once 'db_config.php';
    session_start();
    function redirect($url) {
        header('Location: '.$url);
        die();
    }
    if(isset($_SESSION['user'])){
        redirect("inbox.php");
    }
?>
<html>
    <head>
        <title>Open Encrypt</title>
    </head>
    <body>
        <h1>Under construction.</h1>
    </body>

    <a href="index.html">Home</a>
    <a href="create_account.php">Create Account</a>

    <form action="login.php" method="POST">
  Username: <input type="text" id="username" name="username"><br>
  Password: <input type="password" id="password" name="password"><br>
	<input type="submit" value="Login">
	</form>

    
    <?php
    if (isset($_SESSION['user'])) {
        echo "Logged in user:" . $_SESSION['user'];
    }
    ?>

<?php

// validate form input for username
function validate_username($username,$max_len = 14){
    if (empty($username)) {
        echo "Invalid $type: cannot be blank.<br>";
        return False;
    }
    // To check that username only contains alphabets, numbers, and underscores 
    elseif (!preg_match("/^[a-zA-Z0-9_]*$/", $username)) {
        echo "Invalid $type: only letters, numbers, and underscores are allowed.<br>";
        return False;
    }
    elseif (strlen($username) > $max_len) {
        echo "Invalid $type: must be less than 14 characters.<br>";
        return False;
    }
    else{
        return True;
    }
}

// validate form input for passsword
function validate_password($password, $max_len = 24){
    if (empty($password)) {
        echo "Invalid password: cannot be blank.<br>";
        return false;
    }
    // To check that password only contains alphabets, numbers, and underscores 
    elseif (!preg_match("/^[a-zA-Z0-9_-]*$/", $password)) {
        echo "Invalid password: only upper/lowercase letters, numbers, underscores, and hyphens are allowed.<br>";
        return false;
    }
    elseif (strlen($password) > $max_len) {
        echo "Invalid password: must be less than " . $max_len . "characters.<br>";
        return false;
    }
    else{
        echo "Valid password.<br>";
        return true;
    }
}

//check that the username exists in the database
function username_exists($username,$conn){
    $sql_unique = "SELECT COUNT(*) FROM login_info WHERE username = '$username'";
    try{
        if ($result = mysqli_query($conn, $sql_unique)) {
            $row = $result->fetch_assoc();
            if($row['COUNT(*)'] > 0){
                return True;
            }
            else{
                echo "Username does not exist.";
                return False;
            }
        }
    }
    catch (Exception $e) {
        echo "Error: " . $sql_unique . "<br>" . mysqli_error($conn);
    }
}

$username = "";
$valid_username = False;
if( isset($_POST['username'])){
    $username = $_POST['username'];
    $valid_username = validate_username($username,14) && username_exists($username,$conn);
}

$password = "";
$valid_password = False;
if( isset($_POST['password'])){
    $password = $_POST["password"];
    $valid_password = validate_password($password,24);
}

if ($valid_username && $valid_password){

    // form the sql string with the username and hashed password to insert
    $sql_check = "SELECT password FROM login_info WHERE username = '$username'";
    if ($result = mysqli_query($conn, $sql_check)) {
        $row = $result->fetch_assoc();
        if(password_verify($password,$row['password'])){
            echo "Login successful.";
            //$login_token = random_bytes(32);
            //echo bin2hex($login_token);
            $_SESSION['user'] = $username;
            redirect("inbox.php");
        }
    } 
    else {
        echo "Error: " . $sql_check . "<br>" . mysqli_error($conn);
    }
}

mysqli_close($conn);
?>

</html>