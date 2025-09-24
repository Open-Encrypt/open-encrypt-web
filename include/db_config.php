<?php

$host     = 'localhost';
$db       = 'your-db-name-here';
$user     = 'your-username-here';
$password = 'your-password-here';
$port     = 3306;

$conn = new mysqli($host,$user,$password,$db,$port);

/* check connection */
if ($conn->connect_error) {
   echo "Not connected" . $conn->connect_error;
}

?>
