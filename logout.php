<?php
session_start();
unset($_SESSION["user"]);
echo ("Вы покинули нас ...");
echo '<meta http-equiv="refresh" content="3, URL=login.php" > ';



?>