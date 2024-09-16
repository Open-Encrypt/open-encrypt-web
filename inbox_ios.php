<?php
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
    // form a connection to the SQL database
    include_once 'db_config.php';
    header('Content-Type: application/json'); // Set the content type to JSON
    $response = array();
?>

<?php

// Get the raw POST data (JSON input)
$data = json_decode(file_get_contents('php://input'), true);

$response['status'] = 'failure';
$response['from'] = [];
$response['to'] = [];
$response['messages'] = [];

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
        $result['error'] = "Error: " . $sql_insert . "<br>" . mysqli_error($conn);
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
        $response['error'] = "Error: " . $sql_get_messages . "|" . mysqli_error($conn);
    }
}
//retrieve user's public key from database
function get_public_key($username,$conn,&$response){
    if(username_exists($username,"public_keys",$conn)){
        $sql_select = "SELECT public_key FROM `public_keys` WHERE `username` = '$username'";
        try{
            if ($result = mysqli_query($conn, $sql_select)) {
                $row = $result->fetch_assoc();
                array_push($response['public_key'],$row['public_key']);
            }
        }
        catch(Exception $e) {
            $response['error'] = "Error: " . $sql_insert . "|" . mysqli_error($conn);
        }
    }
}
?>

<?php
//check action variable and decide which SQL query to run
if(isset($data['username']) && isset($data['token']) && isset($data['action'])){
    $username = $data['username'];
    $token = $data['token'];
    $secret_key = $data['secret_key'];
    $action = $data['action'];

    if(verify_token($username,$conn,$token)){
        if($action == "get_messages"){
            get_messages($username,$conn,$secret_key,$response);
        }
        if($action == "get_public_key"){
            get_public_key($username,$conn,$response);
        }
    }
}
?>

<?php
echo json_encode($response);
?>