<?php

$DB_SERVER = "localhost:3306";
$DB_NAME = "cyb";
$DB_USER = "cyb";
$DB_PWD_ENCRYPTED = "bgnePCWaNRR75ROxWzF1lA==";
$PATH_TO_KEY = "C:\\keys\\cyb_key.php";

include($PATH_TO_KEY);
$DB_PWD = openssl_decrypt($DB_PWD_ENCRYPTED, "AES-128-CBC", $ENCRYPT_KEY);