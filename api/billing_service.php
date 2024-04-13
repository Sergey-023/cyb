<?php

session_start();
header("Content-Type: application/json; charset=UTF-8");

$sql = "
    SELECT Login, CalcDate, Result FROM calcs
    WHERE Login='Alexey'  
    ORDER BY CalcDate DESC;
";

include("../settings.php");

$conn = mysqli_connect($DB_SERVER, $DB_USER, $DB_PWD, $DB_NAME);
$result = mysqli_query($conn, $sql);
$data = mysqli_fetch_all($result);

mysqli_close($conn);

//echo($data);
//var_dump($data);

echo(json_encode($data));