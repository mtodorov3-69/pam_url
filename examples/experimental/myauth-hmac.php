<?php

// mtodorov, 2022-01-22, Copyleft by GPLv2 or later.
// v0.07.01 2022-02-07 some security hardening
// v0.07 2022-02-07 added unique request serial number protection.
// v0.05 2022-02-06 added experimental hmac-sha512 challenge-response verification
//                      against brute force replay attacks.
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

$serial_file = "/usr/local/etc/myauth/serial";

$ip_address = $_SERVER['REMOTE_ADDR'];
$ip_srv_address = $_SERVER['SERVER_ADDR'];

if ( $ip_address !== $ip_srv_address )
{
	header("HTTP/1.1 403 Forbidden");
	echo "HOST NOT PERMITTED";
	exit(0);
}
else if( isset($_POST["user"]) && isset($_POST["pass"]) && isset($_POST["mode"]) )
{
	$ret=-1;

	$nonce = $_POST["nonce"];
	$serial = $_POST["serial"];
	$hash = $_POST["hash"];
	if (($rawsecret = file_get_contents("/usr/local/etc/myauth/secret")) !== false) {
		$secret = trim($rawsecret);
		$concatstr = $nonce . $_POST["user"] . $_POST["pass"] . $_POST["mode"] . $_POST["clientIP"] . $_POST["serial"] . $secret . $nonce;
		if (strlen($concatstr) > 4096)
			$ret = 407;
		else {
			$myhash = hash("sha512", $concatstr);
			$concatstr = "";
			if ($hash !== $myhash) {
				$secret = "";
				$ret = 401;
			} else {
				$concatstr = $nonce . $serial . $secret . $nonce;
				if (strlen ($concatstr) > 4096)
					$ret = 407;
				else {
					$rethash = hash("sha512", $nonce . $serial . $secret . $nonce);
					$concatstr = "";
					$secret = "";
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
		echo "ACCESS DENIED";
		exit(0);
	}

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
		echo "HOST NOT PERMITTED";
		exit(0);
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
		echo "OK $rethash";
	}
	else if ( $ret >= 400 )
	{
		header("HTTP/1.1 $ret Forbidden");
		echo "HASH MISMATCH";
	}
	else
	{
		header("HTTP/1.1 403 Forbidden");
		echo "ACCESS DENIED";
	}
}
else
{
	header("HTTP/1.1 400 Bad Request");
	echo "ACCESS DENIED";
}
?>
