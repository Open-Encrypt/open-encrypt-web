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
    //define a function which logs out the user
    function logout(){
        // Unset all of the session variables.
        $_SESSION = array();

        // If it's desired to kill the session, also delete the session cookie.
        // Note: This will destroy the session, and not just the session data!
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
                    
        // Finally, destroy the session.
        session_destroy();
        redirect("login.php");
    }
    //define a function which generates public and private keys
    function generate_keys($encryption_method = "ring_lwe"){
        $command = escapeshellcmd('/home/jackson/open_encrypt/openencryptvenv/bin/python3 keygen_' . $encryption_method . '.py');
        $json_string = shell_exec($command);
        try{
            $json_object = json_decode($json_string, true, 512, JSON_THROW_ON_ERROR);
        }
        catch(Exception $e){
            print $e;
        }
        return $json_object;
    }
    //encrypt a message using the given public key
    function encrypt_message($public_key,$plaintext,$encryption_method="ring_lwe"){
        $command = escapeshellcmd('/home/jackson/open_encrypt/openencryptvenv/bin/python3 encrypt_' . $encryption_method . '.py' . ' ' . $public_key . ' ' . $plaintext);
        $encrypted_string = shell_exec($command);
        return $encrypted_string;
    }
    //decrypt a message using the secret key
    function decrypt_message($secret_key,$ciphertext,$encryption_method="ring_lwe"){
        $command = escapeshellcmd('/home/jackson/open_encrypt/openencryptvenv/bin/python3 decrypt_' . $encryption_method . '.py' . ' ' . $secret_key . ' ' . $ciphertext);
        $decrypted_string = shell_exec($command);
        return $decrypted_string;
    }
    //retrieve the public key from the database for the given username
    function fetch_public_key($username,$conn){
        if(username_exists($username,"public_keys",$conn)){
            $sql_select = "SELECT public_key FROM `public_keys` WHERE `username` = '$username'";
            try{
                if ($result = mysqli_query($conn, $sql_select)) {
                    $row = $result->fetch_assoc();
                    return $row['public_key'];
                }
            }
            catch(Exception $e) {
                echo "Error: " . $sql_select . "<br>" . mysqli_error($conn);
            }
        }
    }
    //function to check whether a username exists in login_info table in database users
    function username_exists($username,$table,$conn){
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
            echo "Error: " . $sql_check . "<br>" . mysqli_error($conn);
        }
    }
    // validate user input from forms
    function valid_input($user_input,$max_len){
        if (empty($user_input)) {
            return false;
        }
        // To check that username only contains alphabets, numbers, and underscores 
        elseif (!preg_match("/^[a-zA-Z0-9_]*$/", $user_input)) {
            return false;
        }
        elseif (strlen($user_input) > $max_len) {
            return false;
        }
        else{
            return true;
        }
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
?>
<html>
    <head>
        <title>Open Encrypt</title>
    </head>
    <body>
        <h1>Under construction.</h1>
    </body>

    <a href="index.html">Home</a>
    <a href="inbox.php">Messages</a>
    <form method="post">
        <input type="submit" name="logout" class="button" value="Logout" /> 
    </form>
    
    <?php
    if (isset($_SESSION['user'])) {
        echo "Welcome to your inbox: " . $_SESSION['user'];
    }
    else{
        logout();
    }
    ?>

    <form action="inbox.php" method="POST">
        To: <input type="text" id="to" name="to">
        Message: <input type="text" id="message" name="message">
        <input type="submit" value="Send">
    </form>

    <form method="post">
        <input type="submit" name="key_gen" class="button" value="Generate Keys" />
        <input type="radio" id="ring_lwe" name="encryption_method" value="ring_lwe">
        <label for="ring_lwe">ring-LWE</label>
        <input type="radio" id="module_lwe" name="encryption_method" value="module_lwe">
        <label for="module_lwe">module-LWE</label>
    </form>

    <form method="post">
        <input type="submit" name="save_keys" class="button" value="Save Public Key" />
        <input type="radio" id="ring_lwe" name="encryption_method" value="ring_lwe">
        <label for="ring_lwe">ring-LWE</label>
        <input type="radio" id="module_lwe" name="encryption_method" value="module_lwe">
        <label for="module_lwe">module-LWE</label>
    </form>

    <form method="post">
        <input type="submit" name="view_keys" class="button" value="View Public Key" /> 
    </form>

    <?php
        //if the "key generation" button is pressed and there is a valid user session, generate public/private key pair
        if (isset($_POST['key_gen']) && isset($_SESSION['user']) &&isset($_POST['encryption_method'])){

            $encryption_method = $_POST['encryption_method'];
            $json_keys = generate_keys($encryption_method);

            if($encryption_method == "ring_lwe"){
                $secret_key = implode('', $json_keys["secret"]);
                $public_key_b = implode(',', $json_keys["public_b"]);
                $public_key_a = implode(',', $json_keys["public_a"]);
                $public_key = $public_key_b . "," . $public_key_a;
            }
            if($encryption_method == "module_lwe"){
                $secret_key = implode(',', $json_keys["secret"]);
                $public_key_A = implode(',', $json_keys["public_A"]);
                $public_key_t = implode(',', $json_keys["public_t"]);
                $public_key = $public_key_A . ',' . $public_key_t;
            }
            echo "Secret key: This is private and should be written down and stored safely. It is used to decrypt messages you've received.<br><br>";
            echo $secret_key;
            echo "<br><br>";
            echo "Public key: This is public and is stored on the server. It is used for encrypting messages sent to you.<br><br>";
            echo $public_key;
            echo "<br><br>";

            $_SESSION['public_key'] = $public_key;
        }
    ?>

<?php
    //save public key
    if(isset($_POST['save_keys']) && isset($_SESSION['user']) && isset($_SESSION['public_key']) && isset($_POST['encryption_method'])){
        $username = $_SESSION['user'];
        $public_key = $_SESSION['public_key'];
        $encryption_method = $_POST['encryption_method'];
        // form the sql string to insert the public_key into table public_keys
        if(!username_exists($username,"public_keys",$conn)){
            $sql_insert = "INSERT INTO `public_keys` (`username`, `public_key`, `method`) VALUES ('$username', '$public_key', '$encryption_method')";
            echo "Trying SQL insertion...";
            try{
                if (mysqli_query($conn, $sql_insert)) {
                    echo "Success: $encryption_method public key inserted into SQL database for $username.<br>";
                    unset($_SESSION['public_key']);
                }
            }
            catch(Exception $e) {
                echo "Error: " . $sql_insert . "<br>" . mysqli_error($conn);
            }
        }
        else{
            echo "Public key already exists for $username. Updating public key...<br>";
            $sql_update = "UPDATE public_keys SET public_key = '$public_key', method = '$encryption_method' WHERE username = '$username'";
            try{
                if (mysqli_query($conn, $sql_update)) {
                    echo "Success: $encryption_method public key updated for $username.<br>";
                    unset($_SESSION['public_key']);
                }
            }
            catch(Exception $e) {
                echo "Error: " . $sql_insert . "<br>" . mysqli_error($conn);
            }
        }
    }
?>

<?php
    if(isset($_POST['view_keys']) && isset($_SESSION['user'])){
        $username = $_SESSION['user'];
        echo fetch_public_key($username,$conn);
    }
?>

    <?php
        if (isset($_SESSION['user']) and isset($_POST['to']) and isset($_POST['message'])){
            //set the variables with message data and metadata
            $from_username = $_SESSION['user'];
            $to_username = $_POST['to'];
            $message = $_POST['message'];

            $valid_recipient = valid_input($to_username,14);
            if (!$valid_recipient){
                echo "Error: Invalid recipient.<br>";
            }
            $valid_message = valid_input($message,240);
            if (!$valid_message){
                echo "Error: Invalid message.<br>";
            }
            
            if(username_exists($to_username,"login_info",$conn) and $valid_recipient and $valid_message){
                $public_key = fetch_public_key($to_username,$conn);
                $encrypted_message = encrypt_message($public_key,$message);
                // form the sql string to insert the message into the tables messages
                $sql_insert = "INSERT INTO `messages` (`from`, `to`, `message`) VALUES ('$from_username', '$to_username','$encrypted_message')";
                echo "Trying SQL insertion...";
                try{
                    if (mysqli_query($conn, $sql_insert)) {
                        echo "Success: message sent from $from_username to $to_username.<br>";
                    }
                }
                catch(Exception $e) {
                    echo "Error: " . $sql_insert . "<br>" . mysqli_error($conn);
                }
            }
            else{
                echo "Error: username does not exist or invalid recipient or invalid message.<br>";
            }
        }
    ?>

    <?php
        echo "-----------------------------------------------------------<br><br>";
    ?>

    <form method="post">
        <label for="secret_key">Secret Key:</label>
        <input type="text" id="secret_key" name="secret_key">
        <input type="submit" name="decrypt_messages" class="button" value="Decrypt Messages" /> 
    </form>

    <form method="post">
        <input type="submit" name="view_messages" class="button" value="View Messages" /> 
    </form>

    <?php
        //display all the encrypted messages sent to the current user
        if(isset($_SESSION['user']) && isset($_POST['view_messages'])){

            $username = $_SESSION['user'];
            $sql_get_messages = "SELECT * FROM messages WHERE `to` = '$username'";
            echo "Trying to retrieve messages...<br><br>";
            try{
                if ($result = mysqli_query($conn, $sql_get_messages)) {
                    echo "retrieved messages successfully.<br><br>";
                    while($row = $result->fetch_assoc()){
                        echo $row['from'] . "-->" . $row['to'] . ": ";
                        echo $row['message'];
                        echo "<br>";
                    }
                }
            }
            catch(Exception $e) {
                echo "Error: " . $sql_get_messages . "<br>" . mysqli_error($conn);
            }
        }
    ?>

<?php   
        //decrypt messages sent to the current user using the provided secret key
        if(isset($_SESSION['user']) && isset($_POST['decrypt_messages']) && isset($_POST['secret_key'])){

            $username = $_SESSION['user'];
            $secret_key = $_POST['secret_key'];

            if (!valid_secret_key($secret_key)){
                echo "Error: Invalid secret key.";
            }
            else{
                $sql_get_messages = "SELECT * FROM messages WHERE `to` = '$username'";
                try{
                    if ($result = mysqli_query($conn, $sql_get_messages)) {
                        echo "Retrieved messages successfully...";
                        echo "Trying to decrypt messages...<br><br>";
                        while($row = $result->fetch_assoc()){
                            echo $row['from'] . "-->" . $row['to'] . ": ";
                            $decrypted_message = decrypt_message($secret_key,$row['message']);
                            echo $decrypted_message;
                            echo "<br>";
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
        if(array_key_exists('logout', $_POST)) { 
            logout();
        }
    ?>

</html>