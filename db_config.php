<?php

$host     = 'localhost';
$db       = 'users';
$user     = 'jackson';
$password = 'whatawonderfulworld';
$port     = 3306;

$conn = new mysqli($host,$user,$password,$db,$port);

/* check connection */
if ($conn->connect_error) {
   echo "Not connected" . $conn->connect_error;
}

?>
