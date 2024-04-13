<?php
  session_start();
  if (!isset($_SESSION["user"])) {
    echo '<meta http-equiv="refresh" content="3, URL=login.php" > ';
    die("Требуется логин! Вы будете перенаправлены через несколько секунд");
  }
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
    
    <script>
      function plus(){
        var x, y, z;
        x = parseInt(document.getElementById("x").value);
        y = parseInt(document.getElementById("y").value);
        z = x + y;
        document.getElementById("z").value = z;
        //document.getElementById("plus").style.backgroundColor = "pink";
        document.getElementById("plus").classList.add("selected");
        document.getElementById("minus").classList.remove("selected");
      }
      
      function minus(){
        var x, y, z;
        x = parseInt(document.getElementById("x").value);
        y = parseInt(document.getElementById("y").value);
        z = x - y;
        document.getElementById("z").value = z;
        document.getElementById("minus").classList.add("selected");
        document.getElementById("plus").classList.remove("selected");
      }
    </script>
  </head>
  <body>
    <h1>Калькулятор на чистом JS</h1>
    <input id="x"/> <br />
    <input id="y"/> <br />
    <button id="plus" onclick="plus();" >+</button>
    <button id="minus" onclick="minus();">-</button> <br />
    <input id="z"/>
  </body>
</html>