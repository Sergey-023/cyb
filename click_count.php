<?php
    session_start();
?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clicks</title>
</head>
<body>
    <h1>Клики на PHP</h1>
    <?php
        if (isset($_SESSION["clicks"])){
            $i = $_SESSION["clicks"];
        }
        else {
            $i = -1;
        }
        $i = $i + 1;
        $_SESSION["clicks"] = $i;
        echo "clicks: $i <br />"
    ?>
    <form>
        <button name="btn" onclick="count();">Click me</button>
    </form>
</body>
</html>