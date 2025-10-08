<?php
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);

    // form a connection to the SQL database
    include_once 'include/db_config.php';

    // Initialize Database object
    include_once 'include/Database.php';
    $db = new Database($conn);

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
        $binary_path = "/var/www/open-encrypt.com/html/bin/";
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
        $binary_path = "/var/www/open-encrypt.com/html/bin/";
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
        $binary_path = "/var/www/open-encrypt.com/html/bin/";
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
        $binary_path = "/var/www/open-encrypt.com/html/bin/";
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
    // Check whether a username exists in the given table
    function username_exists(Database $db, string $username, string $table): bool {
        $allowed_tables = ["login_info", "public_keys"];
        if (!in_array($table, $allowed_tables)) {
            throw new Exception("Invalid table name");
        }

        $query = "SELECT COUNT(*) FROM `$table` WHERE username = ?";
        $count = $db->count($query, [$username], "s");
        return $count > 0;
    }
    // fetch the public key for a given username
    function fetch_public_key(Database $db, string $username): ?string {
        if (!username_exists($db, $username, "public_keys")) {
            return null;
        }

        $row = $db->fetchOne(
            "SELECT public_key FROM public_keys WHERE username = ?",
            [$username],
            "s"
        );

        return $row['public_key'] ?? null;
    }
    // Fetch encryption method for a username
    function fetch_encryption_method(Database $db, string $username): ?string {
        if (!username_exists($db, $username, "public_keys")) {
            return null;
        }

        $row = $db->fetchOne(
            "SELECT method FROM public_keys WHERE username = ?",
            [$username],
            "s"
        );

        return $row['method'] ?? null;
    }
    // validate username input from form
    function valid_username($username,$max_len){
        if (empty($username)) {
            return false;
        }
        // To check that username only contains alphabets, numbers, and underscores 
        if (!preg_match("/^[a-zA-Z0-9_]*$/", $username)) {
            return false;
        }
        if (strlen($username) > $max_len) {
            return false;
        }
        return true;
    }
    // validate message input from form
    function valid_message($message,$max_len){
        if (empty($message)) {
            return false;
        }
        // To check that message only contains alphabets, numbers, underscores, spaces
        if (!preg_match("/^[a-zA-Z0-9_ !?.:;~@#,()+=&$-]*$/", $message)) {
            return false;
        }
        if (strlen($message) > $max_len) {
            return false;
        }
        return true;
    }
    // validate user input for secret keys
    function valid_secret_key($secret_key, $encryption_method = "ring_lwe") {
        // check if secret key is empty
        if (empty($secret_key)) {
            return false;
        }

        // check if it's a valid base64 string
        if (!preg_match("/^[A-Za-z0-9+\/]+={0,2}$/",$secret_key)) {
            echo "Error: " . "secret key is not valid base64 string.";
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
        if (!preg_match("/^[A-Za-z0-9+\/]+={0,2}$/",$public_key)) {
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

    <!-- Simple form to send a message -->
    <form action="inbox.php" method="POST" style="max-width: 400px; padding: 10px; border: 1px solid #000; background: #fff; color: #000; text-align: left;">
        <label for="to">To:</label><br>
        <input type="text" id="to" name="to" style="width: 100%; margin-bottom: 10px; border: 1px solid #000; padding: 5px;"><br>

        <label for="message">Message:</label><br>
        <input type="text" id="message" name="message" style="width: 100%; margin-bottom: 10px; border: 1px solid #000; padding: 5px;"><br>

        <input type="submit" value="Send" style="background: #000; color: #fff; border: none; padding: 8px 12px; cursor: pointer;">
    </form>

    <form method="post">
        <input type="submit" name="key_gen" class="button" value="Generate Keys" />
        <input type="radio" id="ring_lwe" name="encryption_method" value="ring_lwe">
        <label for="ring_lwe">ring-LWE</label>
        <input type="radio" id="module_lwe" name="encryption_method" value="module_lwe">
        <label for="module_lwe">module-LWE</label>
    </form>

    <form method="post">
        <input type="submit" name="save_keys" class="button" value="Save Public Key (to Server)" />
    </form>

    <form method="post">
        <input type="submit" name="view_keys" class="button" value="View Public Key" /> 
    </form>

    <script>
        function copyKey(divId) {
            const keyDiv = document.getElementById(divId);
            if (!keyDiv) return;

            // Use textContent, not innerText
            let keyText = keyDiv.textContent;

            // Remove only newline characters from chunk_split
            keyText = keyText.replace(/\r?\n/g, '');

            navigator.clipboard.writeText(keyText).then(() => {
                alert("Key copied to clipboard!");
            }).catch(err => {
                console.error("Failed to copy: ", err);
            });
        }

        function downloadKey(elementId, filename) {
            const el = document.getElementById(elementId);
            if (!el) return;

            // Use textContent only
            let text = el.textContent;

            // Remove newlines from chunk_split only
            text = text.replace(/\r?\n/g, '');

            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);

            URL.revokeObjectURL(url);
        }
    </script>

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

            // display secret key to user in scrollable box
            echo "Secret key ($encryption_method): This is private and should be written down and stored safely. It is used to decrypt messages you've received from others.<br><br>";
            echo '<div style="display:inline-block;max-height:300px;overflow-y:auto;padding:10px;border:1px solid #ccc;background:#f9f9f9;font-family:monospace;white-space:pre;" id="secret_key_box">';
            echo chunk_split($secret_key, 64, "\n"); // display the secret key in chunks of 64 characters per line
            echo '</div><br>';
            // buttons to save and copy secret key
            echo '<button onclick="copyKey(\'secret_key_box\')">Copy Secret Key</button> ';
            echo '<button onclick="downloadKey(\'secret_key_box\', \'secret.key\')">Save Secret Key</button>';
            
            echo "<br><br>";
            
            // display public key to user in scrollable box
            echo "Public key ($encryption_method): This your public key. It is used by others to encrypt messages sent to you. Click \"Save Public Key (to server)\" to store it and register it to your account.<br><br>";
            echo '<div style="display:inline-block;max-height:300px;overflow-y:auto;padding:10px;border:1px solid #ccc;background:#f9f9f9;font-family:monospace;white-space:pre;" id="public_key_box">';
            echo chunk_split($public_key, 64, "\n"); // display the public key in chunks of 64 characters per line
            echo '</div><br>';
            //buttons to save and copy public key
            echo '<button onclick="copyKey(\'public_key_box\')">Copy Public Key</button> ';
            echo '<button onclick="downloadKey(\'public_key_box\', \'public.key\')">Save Public Key</button>';

            echo "<br><br>";

            //set the public key and encryption method as session variables to be used for "save keys"
            $_SESSION['public_key'] = $public_key;
            $_SESSION['encryption_method'] = $encryption_method;
        }
    ?>

<?php
// Save public key securely using Database class
if (isset($_POST['save_keys'], $_SESSION['user'], $_SESSION['public_key'], $_SESSION['encryption_method'])) {
    $username = $_SESSION['user'];
    $public_key = $_SESSION['public_key'];
    $encryption_method = $_SESSION['encryption_method'];

    if (!valid_public_key($public_key, $encryption_method)) {
        echo "Error: Invalid public key.";
        return;
    }

    // Check if public key already exists
    $row = $db->fetchOne(
        "SELECT username FROM public_keys WHERE username = ?",
        [$username],
        "s"
    );

    if ($row === null) {
        // INSERT
        $success = $db->execute(
            "INSERT INTO public_keys (username, public_key, method) VALUES (?, ?, ?)",
            [$username, $public_key, $encryption_method],
            "sss"
        );

        if ($success) {
            echo "Success: $encryption_method public key inserted into SQL database for $username.<br>";
            unset($_SESSION['public_key'], $_SESSION['encryption_method']);
        } else {
            echo "Error: Failed to insert public key.<br>";
        }
    } else {
        // UPDATE
        $success = $db->execute(
            "UPDATE public_keys SET public_key = ?, method = ? WHERE username = ?",
            [$public_key, $encryption_method, $username],
            "sss"
        );

        if ($success) {
            echo "Success: $encryption_method public key updated for $username.<br>";
            unset($_SESSION['public_key'], $_SESSION['encryption_method']);
        } else {
            echo "Error: Failed to update public key.<br>";
        }
    }
}
?>


<?php
    //view public key and encryption method
    if(isset($_POST['view_keys']) && isset($_SESSION['user'])){
        $username = $_SESSION['user'];
        $public_key = fetch_public_key($db,$username);
        $encryption_method = fetch_encryption_method($db,$username);
        $is_valid = valid_public_key($public_key, $encryption_method);
        if (!$is_valid) {
            echo "Error: Invalid public key stored for $username.<br>";
            return;
        }
        // display public key to user in scrollable box
        echo "Public key ($encryption_method): This your public key. It is used by others to encrypt messages sent to you. Click \"Save Public Key\" to save it to the server.<br><br>";
        echo '<div style="display:inline-block;max-height:300px;overflow-y:auto;padding:10px;border:1px solid #ccc;background:#f9f9f9;font-family:monospace;white-space:pre;">';
        echo chunk_split($public_key, 64, "\n"); // display the public key in chunks of 64 characters per line
        echo '</div>';
    }
?>

<?php
// Send message using Database class
if (isset($_SESSION['user'], $_POST['to'], $_POST['message'])) {
    $from_username = $_SESSION['user'];
    $to_username = $_POST['to'];
    $message = $_POST['message'];

    // Validate recipient and message
    $valid_recipient = valid_username($to_username, 14);
    $valid_message = valid_message($message, 240);

    if (!$valid_recipient) {
        echo "Error: Invalid recipient.<br>";
        return;
    }

    if (!$valid_message) {
        echo "Error: Invalid message.<br>";
        return;
    }

    // Check if recipient exists
    $recipient = $db->fetchOne(
        "SELECT username FROM login_info WHERE username = ?",
        [$to_username],
        "s"
    );

    if ($recipient === null) {
        echo "Error: Recipient does not exist.<br>";
        return;
    }

    // Get recipient's public key and encryption method
    $public_key_row = $db->fetchOne(
        "SELECT public_key, method FROM public_keys WHERE username = ?",
        [$to_username],
        "s"
    );

    if ($public_key_row === null || !valid_public_key($public_key_row['public_key'], $public_key_row['method'])) {
        echo "Error: Recipient's public key is invalid or missing.<br>";
        return;
    }

    $public_key = $public_key_row['public_key'];
    $encryption_method = $public_key_row['method'];

    // Encrypt the message
    $encrypted_message = encrypt_message($public_key, $message, $encryption_method);

    // Insert the message
    $success = $db->execute(
        "INSERT INTO messages (`from`, `to`, `message`, `method`) VALUES (?, ?, ?, ?)",
        [$from_username, $to_username, $encrypted_message, $encryption_method],
        "ssss"
    );

    if ($success) {
        echo "Success: message sent from $from_username to $to_username using $encryption_method.<br>";
    } else {
        echo "Error: Failed to send message.<br>";
    }
}
?>


    <hr style="border: 1px solid black;">

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
// helper function to display messages depending on whether decryption is requested
function display_messages(Database $db, string $username, string $seckey_tempfile = null, string $encryption_method = null) {
    try {
        // Fetch all messages for this user
        $messages = $db->fetchAll(
            "SELECT `id`, `from`, `to`, `message`, `method` FROM `messages` WHERE `to` = ? ORDER BY `id` ASC",
            [$username],
            "s"
        );

        if (empty($messages)) {
            echo "No messages found.<br>";
            return;
        }

        echo $seckey_tempfile ? 
            "Retrieved messages successfully...<br>Trying to decrypt messages...<br><br>" :
            "Retrieved messages successfully.<br><br>";

        foreach ($messages as $row) {
            echo "[id=" . htmlspecialchars($row['id']) . "] ";
            echo htmlspecialchars($row['from']) . " --> " . htmlspecialchars($row['to']);
            if (!$seckey_tempfile) {
                echo " (" . htmlspecialchars($row['method']) . ")";
            }
            echo ": ";

            if ($seckey_tempfile && $encryption_method) {
                // Only decrypt messages that match encryption method
                if ($row['method'] !== $encryption_method) {
                    echo "[different encryption method]<br>";
                    continue;
                }

                $ct_tempfile = make_tempfile('ct_');
                file_put_contents($ct_tempfile, $row['message']);

                $out = run_decrypt_with_files($seckey_tempfile, $ct_tempfile, $encryption_method);
                echo htmlspecialchars($out);

                @unlink($ct_tempfile);
                echo "<br>";
            } else {
                // Display encrypted message
                echo '<div style="display:inline-block;max-height:300px;overflow-y:auto;padding:10px;border:1px solid #ccc;background:#f9f9f9;font-family:monospace;white-space:pre;">';
                echo chunk_split(htmlspecialchars($row['message']), 64, "\n");
                echo '</div><br>';
            }
        }

    } catch (Exception $e) {
        echo "Error fetching messages: " . $e->getMessage() . "<br>";
    }
}
?>

<?php
// View messages (encrypted) if "View Messages" button is pressed
if (isset($_SESSION['user'], $_POST['view_messages'])) {
    $username = $_SESSION['user'];
    display_messages($db, $username);
}
?>

<?php
// Decrypt messages if secret key file is uploaded
if (isset($_SESSION['user'], $_POST['decrypt_messages'], $_POST['encryption_method'])) {
    $username = $_SESSION['user'];
    $encryption_method = $_POST['encryption_method'];

    // ensure the secret key file was uploaded without errors
    if (!isset($_FILES['secret_key_file']) || $_FILES['secret_key_file']['error'] !== UPLOAD_ERR_OK) {
        echo "Error: Secret key file is required.";
        return;
    }

    // create a temporary file to store the uploaded secret key
    $tmp_name = $_FILES['secret_key_file']['tmp_name'];
    $seckey_tempfile = make_tempfile('seckey_');

    // move the uploaded file to the temp location
    if (!move_uploaded_file($tmp_name, $seckey_tempfile) && !copy($tmp_name, $seckey_tempfile)) {
        echo "Error: Failed to store uploaded secret key.";
        return;
    }

    // read and validate the secret key
    $secret_key_contents = trim(file_get_contents($seckey_tempfile));
    if ($secret_key_contents === false || !valid_secret_key($secret_key_contents, $encryption_method)) {
        echo "Error: Invalid secret key.";
        return;
    }

    // display decrypted messages to the user
    display_messages($db, $username, $seckey_tempfile, $encryption_method);

    if (file_exists($seckey_tempfile)) {
        @unlink($seckey_tempfile);
    }
}
?>



    <?php
        if(array_key_exists('logout', $_POST)) { 
            logout();
        }
    ?>
</body>
</html>