<?php
// Обязательно убрать отсюда в реальности
$pwd = "P@ssw0rd";
echo openssl_encrypt($pwd, "AES-128-CBC", 'Pa$$w0rd');