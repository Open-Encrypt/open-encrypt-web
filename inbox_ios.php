<?php
ini_set('display_errors', 0);  // Display errors in the browser (for debugging purposes)
ini_set('log_errors', 1);      // Enable error logging
ini_set('error_log', '/var/www/open-encrypt.com/html/error.log');  // Absolute path to the error log file
error_reporting(E_ALL);         // Report all types of errors
// form a connection to the SQL database
include_once 'db_config.php';
header('Content-Type: application/json'); // Set the content type to JSON
$response = array();
// Get the raw POST data (JSON input)
$data = json_decode(file_get_contents('php://input'), true);
$response['status'] = 'failure';
?>

<?php
//fetch the token from the database and verify it matches the given token
function verify_token($username,$conn,$token){
    $sql_select_token = "SELECT token FROM login_info WHERE username = '$username'";
    try{
        if ($result = mysqli_query($conn, $sql_select_token)) {
            $row = $result->fetch_assoc();
            return $row['token'] == $token;
        }
    }
    catch(Exception $e) {
        $response['error'] = "Exception: " . $e->getMessage();
        return false;
    }
}
//decrypt a message using the secret key
function decrypt_message($secret_key,$ciphertext){
    $command = escapeshellcmd('/home/jackson/open_encrypt/openencryptvenv/bin/python3 decrypt.py' . ' ' . $secret_key . ' ' . $ciphertext);
    $decrypted_string = shell_exec($command);
    return $decrypted_string;
}
// validate user input from forms
function valid_secret_key($secret_key){
    if (empty($secret_key)) {
        return false;
    }
    // To check that username only contains alphabets, numbers, and underscores 
    elseif (!preg_match("/^[0-1]*$/", $secret_key)) {
        return false;
    }
    elseif (strlen($secret_key) > 16) {
        return false;
    }
    else{
        return true;
    }
}
//function to get messages from the database
function get_messages($username,$conn,$secret_key,&$response){
    $response['from'] = [];
    $response['to'] = [];
    $response['messages'] = [];
    $valid_secret_key = valid_secret_key($secret_key);
    $sql_get_messages = "SELECT * FROM messages WHERE `to` = '$username'";
    try{
        if ($result = mysqli_query($conn, $sql_get_messages)) {
            $response['status'] = 'success';
            while($row = $result->fetch_assoc()){
                array_push($response['from'],$row['from']);
                array_push($response['to'],$row['to']);
                if($valid_secret_key){
                    array_push($response['messages'],decrypt_message($secret_key,$row['message']));
                }
                else{
                    array_push($response['messages'],$row['message']);
                }
            }
        }
    }
    catch(Exception $e) {
        $response['error'] = "Exception: " . $e->getMessage();
    }
}
//function to check whether a username exists in login_info table in database users
function username_exists($username,$conn,$table,&$response){
    $sql_check = "SELECT COUNT(*) FROM $table WHERE username = '$username'";
    try{
        if ($result = mysqli_query($conn, $sql_check)) {
            $row = $result->fetch_assoc();
            if($row['COUNT(*)'] > 0){
                return true;
            }
            else{
                return false;
            }
        }
    }
    catch(Exception $e) {
        $response['error'] = "Exception: " . $e->getMessage();
    }
}
//retrieve user's public key from database
function get_public_key($username,$conn,&$response){
    if(username_exists($username,$conn,"public_keys",$response)){
        $sql_select = "SELECT public_key FROM `public_keys` WHERE `username` = '$username'";
        try{
            if ($result = mysqli_query($conn, $sql_select)) {
                $row = $result->fetch_assoc();
                $response['public_key'] = $row['public_key'];
                $response['status'] = "success";
            }
        }
        catch(Exception $e) {
            $response['error'] = "Exception: " . $e->getMessage();
        }
    }
}
//define a function which generates public and private keys
function generate_keys(&$response){
    $command = escapeshellcmd('/home/jackson/open_encrypt/openencryptvenv/bin/python3 keygen.py');
    $json_string = shell_exec($command);
    try{
        $json_object = json_decode($json_string, true, 512, JSON_THROW_ON_ERROR);
    }
    catch(Exception $e){
        print $e;
    }
    $secret_key = implode('', $json_object["secret"]);
    $public_key_b = implode(',', $json_object["public_b"]);
    $public_key_a = implode(',', $json_object["public_a"]);
    $response['public_key'] = $public_key_b . "," . $public_key_a;
    $response['secret_key'] = $secret_key;
    $response['status'] = "success";
}
// Function to store public key in the database
function save_public_key($username, $conn, $public_key, &$response) {
    // Check if the username already exists in the public_keys table
    if (!username_exists($username, $conn,"public_keys", $response)) {
        // Insert the public key into the database
        $sql_insert = "INSERT INTO `public_keys` (`username`, `public_key`) VALUES ('$username', '$public_key')";
        try {
            if (mysqli_query($conn, $sql_insert)) {
                // Check if rows were affected
                if (mysqli_affected_rows($conn) > 0) {
                    $response['status'] = "success";
                    error_log("Public key inserted successfully for username: $username");
                } else {
                    $response['status'] = "failure";
                    $response['error'] = "Insert query did not affect any rows.";
                    error_log("Insert query did not affect any rows for username: $username");
                }
            } else {
                $response['status'] = "failure";
                $response['error'] = "Insert query failed: " . mysqli_error($conn);
                error_log("Insert query failed for username: $username with error: " . mysqli_error($conn));
            }
        } catch (Exception $e) {
            $response['status'] = "failure";
            $response['error'] = "Exception: " . $e->getMessage();
            error_log("Exception during insert for username: $username with error: " . $e->getMessage());
        }
    } else {
        // Update the existing public key in the database
        $sql_update = "UPDATE public_keys SET public_key = '$public_key' WHERE username = '$username'";
        try {
            if (mysqli_query($conn, $sql_update)) {
                // Check if rows were affected
                if (mysqli_affected_rows($conn) > 0) {
                    $response['status'] = "success";
                    error_log("Public key updated successfully for username: $username");
                } else {
                    $response['status'] = "failure";
                    $response['error'] = "Update query did not affect any rows.";
                    error_log("Update query did not affect any rows for username: $username");
                }
            } else {
                $response['status'] = "failure";
                $response['error'] = "Update query failed: " . mysqli_error($conn);
                error_log("Update query failed for username: $username with error: " . mysqli_error($conn));
            }
        } catch (Exception $e) {
            $response['status'] = "failure";
            $response['error'] = "Exception: " . $e->getMessage();
            error_log("Exception during update for username: $username with error: " . $e->getMessage());
        }
    }
}

?>

<?php
//check action variable and decide which SQL query to run
if(isset($data['username']) && isset($data['token']) && isset($data['action'])){
    $username = $data['username'];
    $token = $data['token'];
    $action = $data['action'];

    if(verify_token($username,$conn,$token)){
        if($action == "get_messages"){
            $secret_key = $data['secret_key'];
            get_messages($username,$conn,$secret_key,$response);
        }
        if($action == "get_public_key"){
            get_public_key($username,$conn,$response);
        }
        if($action == "generate_keys"){
            generate_keys($response);
        }
        if($action == "save_public_key"){
            $public_key = $data['public_key'];
            save_public_key($username,$conn,$public_key,$response);
        }
    }
}
?>

<?php
echo json_encode($response);
?>