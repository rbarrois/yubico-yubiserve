<?php
/*

Written by Alessio Periloso <nospam *at* periloso.it>
Version 1.0: 21/05/2010

Licensed under GPL License (see LICENSE file)

*/

$filename = 'yubikeys.sqlite';



if (!extension_loaded('mcrypt')) {
    die("mcrypt not loaded!");
}

$logfacility = LOG_LOCAL0;
openlog("yubiserve", LOG_PID, $logfacility)
  or die("ERR Syslog open error\n");

if (!($db = new SQLiteDatabase($filename))) {
  syslog(LOG_INFO, "Cannot access database");
  die("Cannot access database");
}

?>
