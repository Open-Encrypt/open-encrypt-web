<html>
    <head>
        <title>Open Encrypt</title>
    </head>
    <body>
        <h1>Under construction.</h1>
    </body>

    <a href="index.html">Home</a>
    <a href="login.php">Login</a>

    <form action="create_account.php" method="POST">
  Username: <input type="text" id="username" name="username"><br>
  Password: <input type="password" id="password" name="password"><br>
	<input type="submit" value="Create account">
	</form>

<?php

error_reporting(E_ALL);
ini_set('display_errors', '1');

// form a connection to the SQL database
include_once 'db_config.php';

$username = "";
$valid_username = False;

if( count($_POST) > 0){
    $username = $_POST["username"];
}
// validate form input for username
if (empty($username)) {
    echo "Invalid username: cannot be blank.<br>";
}
// To check that username only contains alphabets, numbers, and underscores 
elseif (!preg_match("/^[a-zA-Z0-9_]*$/", $username)) {
    echo "Invalid username: only letters, numbers, and underscores are allowed.<br>";
}
elseif (strlen($username) > 14) {
    echo "Invalid username: must be less than 14 characters.<br>";
}
else{
    //check that the username to be added is unique
    $sql_unique = "SELECT COUNT(*) FROM login_info WHERE username = '$username'";
    if ($result = mysqli_query($conn, $sql_unique)) {
        $row = $result->fetch_assoc();
        if($row['COUNT(*)'] > 0){
            echo "Invalid username: not unique.<br>";
        }
        else{
            echo "Username is unique.<br>";
            $valid_username = True;
        }
    } 
    else {
        echo "Error: " . $sql_unique . "<br>" . mysqli_error($conn);
    }
}

$password = "";
$valid_password = False;
if( count($_POST) > 0){
    $password = $_POST["password"];
}

// validate form input for passsword
if (empty($password)) {
    echo "Invalid password: cannot be blank.<br>";
}
// To check that password only contains alphabets, numbers, and underscores 
elseif (!preg_match("/^[a-zA-Z0-9_-]*$/", $password)) {
    echo "Invalid password: only upper/lowercase letters, numbers, underscores, and hyphens are allowed.<br>";
}
elseif (strlen($password) > 24) {
    echo "Invalid password: must be less than 24 characters.<br>";
}
else{
    echo "Valid password.<br>";
    $valid_password = True;
    $hashed_password = password_hash($password,PASSWORD_DEFAULT);
}

if ($valid_username and $valid_password){

    // form the sql string with the username and hashed password to insert
    $sql_insert = "INSERT INTO login_info (username, password) VALUES ('$username', '$hashed_password')";
    if (mysqli_query($conn, $sql_insert)) {
        echo "New record created successfully for $username.<br>";
    } 
    else {
     echo "Error: " . $sql_insert . "<br>" . mysqli_error($conn);
    }
}
else{
    echo "Invalid input.<br>";
}
mysqli_close($conn);
?>
</html>