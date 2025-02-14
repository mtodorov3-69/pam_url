<?php

// mtodorov, 2022-01-22, Copyleft by GPLv2 or later.
// v0.07.02 2022-02-08 support for sha512, prevent brute force on hash functions
// v0.07.01 2022-02-07 some security hardening
// v0.07 2022-02-07 added unique request serial number protection.
// v0.05 2022-02-06 added experimental hmac-sha512 challenge-response verification
//		      against brute force replay attacks.
// v0.04 2022-02-06 added experimental hmac-sha512 authentication
// v0.03 2022-01-26 enabled multiline comments
// v0.02 2022-01-25 enaled mapping certs to usernames in pamlib-pkcs11 '->' and Paul Wouters' 'username@' notation
// Based on the example from pam_url/examples/auth.php

// we need at least 4 POST data elements. 
// 1. Authentication mode -> PAM_AUTH, PAM_SESS, PAM_ACCT, PAM_PASS
// 2. PSK, Pre Shared Key
// 3. USER
// 4. PASS

// DO SOURCE IP REGION CHECKS HERE, OTHERWISE BRUTEFORCE attacks might occur!!

$ip_address = $_SERVER['REMOTE_ADDR'];
$ip_srv_address = $_SERVER['SERVER_ADDR'];

if ( strncmp($ip_srv_address, "127.", 4) == 0)
{
	$result = dns_get_record($_SERVER['HTTP_HOST'], DNS_A);
	$ip_srv_address = $result[0]["ip"];
}

$hostname = gethostname();

if ( isset ($_SERVER['CONTENT_LENGTH']) )
{
	if ( $_SERVER['CONTENT_LENGTH'] > 4096 )
	{
		// This was most likely a brute force attack.
		header("HTTP/1.1 403 Forbidden");
		echo "ACCESS DENIED";
		error_log("ALERT: Request size overflow from host $ip_address");
		exit(7);
	}
}
else
{
	header("HTTP/1.1 403 Forbidden");
	echo "ACCESS DENIED";
	error_log("ALERT: refused GET request from host $ip_address");
	exit(7);
}

if ( $ip_address != $ip_srv_address )
{
	header("HTTP/1.1 403 Forbidden");
	echo "HOST NOT PERMITTED";
	$remote = gethostbyaddr($ip_address);
	error_log("001: Access denied from host $ip_address on $ip_srv_address, $remote, $hostname");
	exit(7);
}
else if( isset($_POST["user"]) && isset($_POST["pass"]) && isset($_POST["mode"]) )
{
	$ret=-1;

	$nonce = $_POST["nonce"];
	$serial = $_POST["serial"];
	$hash = $_POST["hash"];
	$xor_pass_hex = $_POST["pass"];

	if (strlen($nonce) > 1024 || strlen($serial) > 100 || strlen($hash) > 1024 || strlen($_POST["user"]) > 128
				  || strlen($_POST["pass"]) > 1024 || strlen($_POST["clientIP"]) > 32)
		$ret = 407;
	else if (($rawsecret = file_get_contents("/usr/local/etc/myauth/secret")) !== false) {
		$secret = trim($rawsecret);
		$concatstr = $nonce . $_POST["user"] . $_POST["pass"] . $_POST["mode"] . $_POST["clientIP"] . $serial . $secret . $nonce;
		if (strlen($concatstr) > 4096)
			$ret = 407;
		else {
			$myhash = hash("sha512", $concatstr);
			$concatstr = "";
			if ($hash !== $myhash) {
				$secret = ""; // forget secret as soon as we no longer need it
				$ret = 401;
			} else {
				$concatstr = $nonce . $serial . $secret . $nonce;
				if (strlen ($concatstr) > 4096)  // probably a forged request in a brute force attack
					$ret = 407;
				else {
					$rethash = hash("sha512", $nonce . $serial . $secret . $nonce);
					$concatstr = "";
					$pass = "";
					$xor_pass = hex2bin($xor_pass_hex);
					for ($i = 0; $i < strlen($xor_pass_hex) / 2; $i++)
					     $pass = $pass . ($nonce[$i] ^ $secret[$i] ^ $xor_pass[$i]);
					// error_log ("INFO: decrypted pass=$pass");
					$secret = ""; // forget secret as soon as we no longer need it
					$ret = 0;
				}
			}
		}
	} else {
		$ret = 402;
		$secret = "";
	}

	if ( $ret !== 0 ) {
		header("HTTP/1.1 $ret Forbidden");
		error_log("ALERT: Counterfeit request: Bad hash in request from $ip_address");
		echo "ACCESS DENIED";
		exit(7);
	}

	$serial_file = "/usr/local/etc/myauth/serial";

	if ( $ret == 0 && ($rawserial = file_get_contents($serial_file)) !== false) {
		$myserial = trim($rawserial);
		if ($myserial >= $serial)
			$ret = 405;
		else {
			// remote serial is greater, we are going to the next stage
			if (file_put_contents($serial_file, $serial) == false)
				$ret = 406;
			else
				$ret = 0;
		}
	} else
		$ret = 404;

	if ( $ret !== 0 ) {
		header("HTTP/1.1 $ret Forbidden");
		error_log("ALERT: Possible replay attack: Bad serial in request from $ip_address");
		echo "HOST NOT PERMITTED";
		exit(7);
	}

	switch($_POST["mode"])
	{
		case "PAM_SM_AUTH";
			// Perform authing here
		case "PAM_SM_ACCOUNT";
			// Perform account aging here

			$ret = -1; // by default is no entry

			$path = '/usr/local/etc/vpn-ikev2-authorized';

			if (file_exists($path)) {
			    if (($configuration = file_get_contents($path)) !== false) {
				// enable multiline comments
				$configuration = preg_replace('#\/\*.*\*\/#sU', '', $configuration);
				$lines = preg_split('/\n/', $configuration);
				foreach ($lines as $input_line) {
				    // enable hash # and // C++ style comments in the authorization file
				    $input_line = preg_replace('/(#.*|\/\/.*)$/', '', $input_line);
				    // ignore whitespace and trailing \n
				    $input_line = trim($input_line);
				    if ($input_line == '')
					continue;
				    if (strpos($input_line, ' -> ') !== false) {
					list ($certsn, $username) = explode(' -> ', $input_line);
					if (strcmp($certsn, $_POST['user']) == 0 && posix_getpwnam($username) !== false) {
					    $ret = 0;
					    break;
					}
				    } else if (strcmp($input_line, $_POST['user']) == 0 && strpos($input_line, '@') !== false) {
					list (, $certsnpart) = explode('CN=', $input_line);
					list ($username, ) = explode('@', $certsnpart);
					if (posix_getpwnam($username) !== false) {
					    $ret = 0;
					    break;
					}
				    } else if (strcmp($input_line, $_POST['user']) == 0) {
					$ret = 0;
					break;
				    }
				}
			    }
			}
			break;

		case "PAM_SM_SESSION";
			// Perform session management here
			break;

		case "PAM_SM_PASSWORD";
			// Perform password changes here
			break;
	}

	if( 0 == $ret )
	{
		header("HTTP/1.1 200 OK");
		error_log("002: Access granted to ${_POST['user']} in request from $ip_address");
		echo "OK $rethash";
	}
	else if ( $ret >= 400 )
	{
		header("HTTP/1.1 $ret Forbidden");
		error_log("003: Access denied to ${_POST['user']} in request from $ip_address");
		echo "ACCESS DENIED";
	}
	else
	{
		header("HTTP/1.1 403 Forbidden");
		error_log("004: Access denied to ${_POST['user']} in request from $ip_address");
		echo "ACCESS DENIED";
	}
}
else
{
	header("HTTP/1.1 400 Bad Request");
	error_log("ALERT: 005: Access denied in request from $ip_address");
	echo "ACCESS DENIED";
}
?>
