<?php
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
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
        $binary_path = "/var/www/open-encrypt.com/html/";
        $command = escapeshellcmd($binary_path . ($encryption_method == "ring_lwe" ? "ring-lwe-v0.1.8" : "module-lwe-v0.1.5") . " keygen");
        $json_string = shell_exec($command);
        try{
            $json_object = json_decode($json_string, true, 512, JSON_THROW_ON_ERROR);
        }
        catch(Exception $e){
            print $e;
        }
        return $json_object;
    }
    // Encrypt a message using the given public key
    function encrypt_message($public_key, $plaintext, $encryption_method = "ring_lwe") {
        $binary_path = "/var/www/open-encrypt.com/html/";
        $binary = ($encryption_method == "ring_lwe" ? "ring-lwe-v0.1.8" : "module-lwe-v0.1.5");
        $binary_full = $binary_path . $binary;

        if ($encryption_method == "ring_lwe") {
            // Inline key works fine for ring-lwe
            $command = escapeshellcmd(
                $binary_full 
                . " encrypt "
                . "--pubkey " 
                . escapeshellarg(trim($public_key))
                . " " 
                . escapeshellarg(trim($plaintext))
            ) . " 2>&1"; // capture stderr
        } else {
            // Write public key to a temp file for module-lwe
            $tmp_pubkey_file = tempnam(sys_get_temp_dir(), "pubkey_");
            file_put_contents($tmp_pubkey_file, trim($public_key));

            $command = escapeshellcmd(
                $binary_full 
                . " encrypt "
                . "--pubkey-file " 
                . escapeshellarg($tmp_pubkey_file)
                . " " 
                . escapeshellarg(trim($plaintext))
            ) . " 2>&1"; // capture stderr
        }

        $encrypted_string = shell_exec($command);

        // Optionally clean up temp file
        if (isset($tmp_pubkey_file) && file_exists($tmp_pubkey_file)) {
            unlink($tmp_pubkey_file);
        }

        return $encrypted_string;
    }
    //decrypt a message using the secret key
    function decrypt_message($secret_key,$ciphertext,$encryption_method="ring_lwe"){
        $binary_path = "/var/www/open-encrypt.com/html/";
        $command = escapeshellcmd(
            $binary_path 
            . ($encryption_method == "ring_lwe" ? "ring-lwe-v0.1.8" : "module-lwe-v0.1.5") 
            . " decrypt "
            . "--secret "
            . escapeshellarg(trim($secret_key)) 
            . " " 
            . escapeshellarg(trim($ciphertext))
        ) . " 2>&1";
        $decrypted_string = shell_exec($command);
        return $decrypted_string;
    }
    function make_tempfile($prefix = 'oe_') {
        $tmp = sys_get_temp_dir();
        $name = tempnam($tmp, $prefix);
        if ($name === false) {
            throw new Exception("Unable to create temp file");
        }
        return $name;
    }
    // Decrypt using secret key and ciphertext files
    function run_decrypt_with_files(string $seckey_file, string $ciphertext_file, string $encryption_method) : string {
        $binary_path = "/var/www/open-encrypt.com/html/";
        $binary = ($encryption_method === "ring_lwe")
            ? "ring-lwe-v0.1.8"
            : "module-lwe-v0.1.5";

        $cmd = $binary_path . $binary
            . " decrypt --secret-file " . escapeshellarg($seckey_file)
            . " --ciphertext-file " . escapeshellarg($ciphertext_file)
            . " 2>&1";

        $output = shell_exec($cmd);
        return $output === null ? "" : $output;
    }
    //retrieve the public key from the database for the given username
    function fetch_public_key($username,$conn){
        if(username_exists($username,"public_keys",$conn)){
            $sql_select = "SELECT public_key FROM `public_keys` WHERE `username` = '$username'";
            try{
                if ($result = mysqli_query($conn, $sql_select)) {
                    $row = $result->fetch_assoc();
                    $public_key = $row['public_key'];
                    return $public_key;
                }
            }
            catch(Exception $e) {
                echo "Error: " . $sql_select . "<br>" . mysqli_error($conn);
            }
        }
    }
    //retrieve the encryption method from the database for the given username
    function fetch_encryption_method($username,$conn){
        if(username_exists($username,"public_keys",$conn)){
            $sql_select = "SELECT method FROM `public_keys` WHERE `username` = '$username'";
            try{
                if ($result = mysqli_query($conn, $sql_select)) {
                    $row = $result->fetch_assoc();
                    return $row['method'];
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
        if (!preg_match("/^[a-zA-Z0-9_]*$/", $user_input)) {
            return false;
        }
        if (strlen($user_input) > $max_len) {
            return false;
        }
        return true;
    }
    // validate user input from forms
    function valid_secret_key($secret_key, $encryption_method = "ring_lwe") {
        // check if secret key is empty
        if (empty($secret_key)) {
            return false;
        }

        // check if it's a valid base64 string
        if (base64_encode(base64_decode($secret_key, true)) !== $secret_key) {
            return false;
        }

        // optional: enforce max length depending on method
        if ($encryption_method === "ring_lwe" && strlen($secret_key) > 10936) {
            return false;
        }
        if ($encryption_method === "module_lwe" && strlen($secret_key) > 43704) {
            return false;
        }

        return true;
    }
    // validate user input for public keys
    function valid_public_key($public_key, $encryption_method = "ring_lwe") {
        // check if public key is empty
        if (empty($public_key)) {
            echo "Error: " . "public key is empty.";
            return false;
        }

        // check if it's a valid base64 string
        if (base64_encode(base64_decode($public_key, true)) !== $public_key) {
            echo "Error: " . "public key is not valid base64 string.";
            return false;
        }

        // optional: enforce max length depending on method
        if ($encryption_method === "ring_lwe" && strlen($public_key) > 21856) { // adjust size as needed
            echo "Error: " . "public key exceeds maximum length for ring_lwe.";
            return false;
        }
        if ($encryption_method === "module_lwe" && strlen($public_key) > 393228) {
            echo "Error: " . "public key exceeds maximum length for module_lwe.";
            return false;
        }

        return true;
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
    </form>

    <form method="post">
        <input type="submit" name="view_keys" class="button" value="View Public Key" /> 
    </form>

    <?php
        //if the "key generation" button is pressed and there is a valid user session, generate public/private key pair
        if (isset($_POST['key_gen']) && isset($_SESSION['user']) && isset($_POST['encryption_method'])){

            $encryption_method = $_POST['encryption_method'];
            $json_keys = generate_keys($encryption_method);

            if($encryption_method == "ring_lwe"){
                $secret_key = trim($json_keys["secret"]);
                $public_key = trim($json_keys["public"]);
            }
            if($encryption_method == "module_lwe"){
                $secret_key = trim($json_keys["secret"]);
                $public_key = trim($json_keys["public"]);
            }
            echo "Secret key ($encryption_method): This is private and should be written down and stored safely. It is used to decrypt messages you've received.<br><br>";
            echo $secret_key;
            echo "<br><br>";
            echo "Public key ($encryption_method): This is public and is stored on the server. It is used for encrypting messages sent to you.<br><br>";
            echo $public_key;
            echo "<br><br>";

            //set the public key and encryption method as session variables to be used for "save keys"
            $_SESSION['public_key'] = $public_key;
            $_SESSION['encryption_method'] = $encryption_method;
        }
    ?>

<?php
    //save public key
    if(isset($_POST['save_keys']) && isset($_SESSION['user']) && isset($_SESSION['public_key']) && isset($_SESSION['encryption_method'])){
        $username = $_SESSION['user'];
        $public_key = $_SESSION['public_key'];
        $encryption_method = $_SESSION['encryption_method'];
        valid_public_key($public_key, $encryption_method);
        // form the sql string to insert the public_key into table public_keys
        if(!username_exists($username,"public_keys",$conn)){
            $sql_insert = "INSERT INTO `public_keys` (`username`, `public_key`, `method`) VALUES ('$username', '$public_key', '$encryption_method')";
            echo "Trying SQL insertion...";
            try{
                if (mysqli_query($conn, $sql_insert)) {
                    echo "Success: $encryption_method public key inserted into SQL database for $username.<br>";
                    unset($_SESSION['public_key']);
                    unset($_SESSION['encryption_method']);
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
                    unset($_SESSION['encryption_method']);
                }
            }
            catch(Exception $e) {
                echo "Error: " . $sql_insert . "<br>" . mysqli_error($conn);
            }
        }
    }
?>

<?php
    //view public key and encryption method
    if(isset($_POST['view_keys']) && isset($_SESSION['user'])){
        $username = $_SESSION['user'];
        $public_key = fetch_public_key($username,$conn);
        $encryption_method = fetch_encryption_method($username,$conn);
        $is_valid = valid_public_key($public_key, $encryption_method);
        echo "is_valid: " . ($is_valid ? "true" : "false") . "<br>";
        echo "public_key: " . $public_key . "<br>";
        echo "encryption_method: " . $encryption_method . "<br>";
    }
?>

    <?php
        //send message
        if (isset($_SESSION['user']) and isset($_POST['to']) and isset($_POST['message'])){
            //set the variables with message data and metadata
            $from_username = $_SESSION['user'];
            $to_username = $_POST['to'];
            $message = $_POST['message'];

            //get the encryption method used by $to_username
            $encryption_method = fetch_encryption_method($to_username,$conn);

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
                $encrypted_message = encrypt_message($public_key,$message,$encryption_method);
                // form the sql string to insert the message into the tables messages
                $sql_insert = "INSERT INTO `messages` (`from`, `to`, `message`,`method`) VALUES ('$from_username', '$to_username','$encrypted_message','$encryption_method')";
                echo "Trying SQL insertion...";
                try{
                    if (mysqli_query($conn, $sql_insert)) {
                        echo "Success: message sent from $from_username to $to_username using $encryption_method.<br>";
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

    <form method="post" enctype="multipart/form-data">
    <label for="secret_key_file">Upload Secret Key File:</label>
    <input type="file" id="secret_key_file" name="secret_key_file" accept=".txt,.key" required>
    <br>
    <input type="radio" id="ring_lwe" name="encryption_method" value="ring_lwe" checked>
    <label for="ring_lwe">ring-LWE</label>
    <input type="radio" id="module_lwe" name="encryption_method" value="module_lwe">
    <label for="module_lwe">module-LWE</label>
    <br>
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
                        echo $row['from'] . "-->" . $row['to'] . ' (' . $row['method'] . "): ";
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
if (isset($_SESSION['user']) && isset($_POST['decrypt_messages']) && isset($_POST['encryption_method'])) {
    $username = $_SESSION['user'];
    $encryption_method = $_POST['encryption_method'];

    if (!isset($_FILES['secret_key_file']) || $_FILES['secret_key_file']['error'] !== UPLOAD_ERR_OK) {
        echo "Error: Secret key file is required.";
        return;
    }

    // move secret key file to temp location
    $tmp_name = $_FILES['secret_key_file']['tmp_name'];
    $seckey_tempfile = make_tempfile('seckey_');
    if (!move_uploaded_file($tmp_name, $seckey_tempfile)) {
        if (!copy($tmp_name, $seckey_tempfile)) {
            echo "Error: Failed to store uploaded secret key.";
            return;
        }
    }

    $sql_get_messages = "SELECT * FROM messages WHERE `to` = '" . mysqli_real_escape_string($conn, $username) . "'";
    try {
        if ($result = mysqli_query($conn, $sql_get_messages)) {
            echo "Retrieved messages successfully...<br>Trying to decrypt messages...<br><br>";
            while ($row = $result->fetch_assoc()) {
                echo htmlspecialchars($row['from']) . " --> " . htmlspecialchars($row['to']) . ": ";

                if ($encryption_method !== $row['method']) {
                    echo "[different encryption method]<br>";
                    continue;
                }

                $ciphertext = $row['message'];
                $ct_tempfile = make_tempfile('ct_');
                file_put_contents($ct_tempfile, $ciphertext);

                $out = run_decrypt_with_files($seckey_tempfile, $ct_tempfile, $encryption_method);
                echo "<pre>" . htmlspecialchars($out) . "</pre>";

                @unlink($ct_tempfile);
                echo "<br>";
            }
        } else {
            echo "Error reading messages: " . mysqli_error($conn);
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    } finally {
        if (!empty($seckey_tempfile) && file_exists($seckey_tempfile)) {
            @unlink($seckey_tempfile);
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