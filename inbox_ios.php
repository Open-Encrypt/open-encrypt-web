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
?>

<?php
//display all the encrypted messages sent to the current user
if(isset($data['username']) && isset($data['token'])){
    $username = $data['username'];
    $token = $data['token'];
    if(verify_token($username,$conn,$token)){
        $sql_get_messages = "SELECT * FROM messages WHERE `to` = '$username'";
        try{
            if ($result = mysqli_query($conn, $sql_get_messages)) {
                $response['status'] = 'success';
                while($row = $result->fetch_assoc()){
                    array_push($response['from'],$row['from']);
                    array_push($response['to'],$row['to']);
                    array_push($response['messages'],$row['message']);
                }
            }
        }
        catch(Exception $e) {
            echo "Error: " . $sql_get_messages . "<br>" . mysqli_error($conn);
        }
    }
}
?>

<?php
echo json_encode($response);
?>