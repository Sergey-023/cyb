<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clicks</title>
</head>
<body>
    <h1>Клики на PHP с использованием Cookie</h1>
    <?php
        if (isset($_COOKIE["clicks"])){
            $i = $_COOKIE["clicks"];
        }
        else {
            $i = -1;
        }
        $i = $i + 1;
        setcookie("clicks", $i);
        echo "clicks: $i <br />"
    ?>
    <form>
        <button name="btn" onclick="count();">Click me</button>
    </form>
</body>
</html>