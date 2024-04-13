<?php

session_start();
if (!isset($_SESSION["user"])) {
  die("Требуется логин! Вы будете перенаправлены через несколько секунд");
}
$login = $_SESSION["user"];

$x = $_REQUEST["x"];
$y = $_REQUEST["y"];
$z = $x - $y;

//Логируем в БД
include("../settings.php");

$sql = "
        INSERT INTO Calcs(Login, Result)
        VALUES('$login', $z)
";

//echo $sql;
$conn = mysqli_connect($DB_SERVER, $DB_USER, $DB_PWD, $DB_NAME);
mysqli_query($conn, $sql);

echo($z);