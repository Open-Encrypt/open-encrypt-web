<?php

$host     = 'localhost';
$db       = 'db-name-goes-here';
$user     = 'db-username-goes-here';
$password = 'password-goes-here';
$port     = 3306;

$conn = new mysqli($host,$user,$password,$db,$port);

/* check connection */
if ($conn->connect_error) {
   echo "Not connected" . $conn->connect_error;
}

?>
