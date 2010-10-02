<?
/*

Written by Alessio Periloso <nospam *at* periloso.it>
Version 1.0: 21/05/2010

Licensed under GPL License (see LICENSE file)

*/

require_once 'yubiserve-config.php';
require_once 'yubiserve-utils.php';

if (!isset($_REQUEST["otp"]))
  die ("ERR Missing OTP\n");
$otp = trim($_REQUEST["otp"]);

if ((strlen($otp)<32) || (strlen($otp)>48)) {
  syslog(LOG_INFO, "Malformed OTP: $otp");
  die ("ERR Malformed OTP\n");
}

if (!preg_match("/^([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})$/", $otp, $matches)) {
  syslog(LOG_INFO, "Invalid OTP format: $otp");
  die("ERR Invalid OTP format\n");
 }

$id = $matches[1];
$modhex_ciphertext = $matches[2];

$results = @$db->query("SELECT aeskey, internalname FROM yubikeys WHERE publicname = '$id' AND active = 'true'");
if ($results === false) {
  syslog(LOG_INFO, "Unknown yubikey (internalname: $id)");
  die("ERR Unknown yubikey\n");
}

$row = $results->fetchAll(SQLITE_ASSOC);
if (count($row)>1) {
  syslog(LOG_INFO, "Multiple keys returned! OTP: $otp");
  die("ERR Malformed OTP");
} elseif (count($row)<1) {
  syslog(LOG_INFO, "Unknown yubikey (internalname: $id)");
  die("ERR Unknown yubikey\n");
}

$aeskey = $row[0]['aeskey'];
$internalname = $row[0]['internalname'];

$ciphertext = modhex2hex($modhex_ciphertext);
$plaintext = aes128ecb_decrypt($aeskey, $ciphertext);

$uid = substr($plaintext, 0, 12);
if (strcmp($uid, $internalname) != 0) {
  syslog(LOG_ERR, "UID error: $otp $plaintext: $uid vs $internalname");
  die("ERR Corrupt OTP\n");
}

if (!crc_is_good($plaintext)) {
  syslog(LOG_ERR, "CRC error: $otp: $plaintext");
  die("ERR Corrupt OTP\n");
}

$counter = substr($plaintext, 14, 2) . substr($plaintext, 12, 2);
$low = substr($plaintext, 18, 2) . substr($plaintext, 16, 2);
$high = substr($plaintext, 20, 2);
$use = substr($plaintext, 22, 2);

$timestamp = hexdec($high . $low);
$internalcounter = hexdec($counter . $use);

#print("$counter $use $high $low\n");

$results = @$db->query("SELECT counter, time FROM yubikeys WHERE publicname = '$id' AND active = 'true' AND counter < $internalcounter");
$row = @$results->fetchAll(SQLITE_ASSOC);

if (count($row)!=1) {
  syslog(LOG_ERR, "REPLAYED OTP for yubikey $id (same counter)");
  die("ERR Replayed OTP");
} elseif ((($row[0] >> 8) == ($internalcounter >> 8)) && ($row[1] <= $timestamp)) {
  syslog(LOG_ERR, "REPLAYED OTP for yubikey $id (same timestamp)");
  die("ERR Replayed OTP");
}

print "OK Authentication success";
$results = $db->query("UPDATE yubikeys SET counter = $internalcounter, time = $timestamp WHERE publicname = '$id'");

unset($db);
?>
