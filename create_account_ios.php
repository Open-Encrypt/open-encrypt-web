<?php
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
    // form a connection to the SQL database
    include_once 'db_config.php';
    header('Content-Type: application/json'); // Set the content type to JSON
    $response = array();
    $response['status'] = "failure";
    // Function to generate a secure token
    function generate_token() {
        return bin2hex(random_bytes(16)); // 32 characters long
    }
?>

<?php
// validate form input
function validate($user_input,$max_len,$type= "input",&$response){
    if (empty($user_input)) {
        $response['error'] = "Invalid $type: cannot be blank.";
        return False;
    }
    // To check that username only contains alphabets, numbers, and underscores 
    elseif (!preg_match("/^[a-zA-Z0-9_]*$/", $user_input)) {
        $response['error'] = "Invalid $type: only letters, numbers, and underscores are allowed.";
        return False;
    }
    elseif (strlen($user_input) > $max_len) {
        $response['error'] = "Invalid $type: must be less than 14 characters.";
        return False;
    }
    else{
        return True;
    }
}
//check that the username exists in the database
function username_exists($username,$conn,&$response){
    $sql_unique = "SELECT COUNT(*) FROM login_info WHERE username = '$username'";
    try{
        if ($result = mysqli_query($conn, $sql_unique)) {
            $row = $result->fetch_assoc();
            if($row['COUNT(*)'] > 0){
                $response['error'] = "Username already exists.";
                return True;
            }
            else{
                //$response['error'] = "Username does not exist.";
                return False;
            }
        }
    }
    catch (Exception $e) {
        $response['error'] = $sql_unique . "-->" . mysqli_error($conn);
    }
}
//store the generated login token in the login_info database
function store_token($username,$conn,$token){
    $sql_store_token = "UPDATE login_info SET token = '$token' WHERE username = '$username'";
    try{
        mysqli_query($conn, $sql_store_token);
    }
    catch(Exception $e) {
        $response['error'] = "Error: " . $sql_insert . "|" . mysqli_error($conn);
    }
}
?>

<?php

// Get the raw POST data (JSON input)
$data = json_decode(file_get_contents('php://input'), true);

$username = "";
$valid_username = False;
if(isset($data['username'])){
    $username = $data['username'];
    $valid_username = validate($username,14,"username",$response) && !username_exists($username,$conn,$response);
}
$password = "";
$valid_password = False;
if(isset($data['password'])){
    $password = $data["password"];
    $valid_password = validate($password,14,"password",$response);
}

//if both username and password are valid, login
if ($valid_username && $valid_password){
    //hash the password to 60 characters with salt
    $hashed_password = password_hash($password,PASSWORD_DEFAULT);

    // form the sql string with the username and hashed password to insert
    $sql_insert = "INSERT INTO login_info (username, password) VALUES ('$username', '$hashed_password')";
    if ($result = mysqli_query($conn, $sql_insert)) {
        $response['status'] = 'success';
        $response['token'] = generate_token();
        store_token($username,$conn,$response['token']);
    }
    else {
        $response['error'] = $sql_check . "|" . mysqli_error($conn);
    }
}
?>

<?php
echo json_encode($response);
?>