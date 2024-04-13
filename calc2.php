<?php
  session_start();
  if (!isset($_SESSION["user"])) {
    echo '<meta http-equiv="refresh" content="3, URL=login.php" > ';
    die("Требуется логин! Вы будете перенаправлены через несколько секунд");
  }
  $login = $_SESSION["user"];
?>
<html>
  <head>
    <title>Калькулятор</title>
    <meta charset="utf-8" />
    <style>
      input {
        width: 120px;
        margin-bottom: 6px;
        text-align: center;
      }
      
      button {
        width: 58px;
        margin-bottom: 6px;
      }

      .selected {
        background-color: pink;
      }
    </style>
    
    
  </head>
  <body>
    <h1>Калькулятор на PHP</h1>
    <?php
      $x = 0; $y = 0; $z = 0;
      if (isset($_REQUEST["x"])) {
      $x = $_REQUEST["x"];
      $y = $_REQUEST["y"];
      if (isset($_REQUEST["plus"])) {
        $z = $x + $y;
        }else{
        $z = $x - $y;
        }
      }
    //Логируем в БД
    include("settings.php");

$sql = "
        INSERT INTO Calcs(Login, Result)
        VALUES('$login', $z)
";

//echo $sql;
$conn = mysqli_connect($DB_SERVER, $DB_USER, $DB_PWD, $DB_NAME);
$result = mysqli_query($conn, $sql);




      //echo("Result: $z");
    ?>  
      <form>
      <input name="x" value="<?=$x?>"/> <br />
      <input name="y" value="<?=$y?>"/> <br />
      <button name="plus">+</button>
      <button name="minus">-</button> <br />
      <input value="<?=$z?>"/>
    </form>
  </body>
</html>