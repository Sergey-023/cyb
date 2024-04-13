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
        document.getElementById("z").value = "Wait!";

        var x, y, z;
        x = parseInt(document.getElementById("x").value);
        y = parseInt(document.getElementById("y").value);
        
        var xhr = new XMLHttpRequest();
        var url = "api/plus.php?x=" + x + "&y=" + y;
        xhr.open("GET", url);
        xhr.onload = function() {
          console.log(xhr.responseText);
          z = xhr.responseText;
          document.getElementById("z").value = z;
          document.getElementById("plus").classList.add("selected");
          document.getElementById("minus").classList.remove("selected");
        }
        xhr.send();
      }
      
      function minus(){
      //   var x, y, z;
      //   x = parseInt(document.getElementById("x").value);
      //   y = parseInt(document.getElementById("y").value);
      //   z = x - y;
      //   document.getElementById("z").value = z;
      //   document.getElementById("minus").classList.add("selected");
      //   document.getElementById("plus").classList.remove("selected");
      document.getElementById("z").value = "Wait!";

      var x, y, z;
      x = parseInt(document.getElementById("x").value);
      y = parseInt(document.getElementById("y").value);

      var xhr = new XMLHttpRequest();
      var url = "api/plus.php?x=" + x + "&y=" + y;
xhr.open("GET", url);
xhr.onload = function() {
  console.log(xhr.responseText);
  z = xhr.responseText;
  document.getElementById("z").value = z;
  document.getElementById("plus").classList.add("selected");
  document.getElementById("minus").classList.remove("selected");
}
xhr.send();
    
    
    }
    </script>
  </head>
  <body>
    <h1>Калькулятор с запросом веб сервисов через JS</h1>
    <input id="x" autocomplete="off"/> <br />
    <input id="y" autocomplete="off"/> <br />
    <button id="plus" onclick="plus();" >+</button>
    <button id="minus" onclick="minus();">-</button> <br />
    <input id="z"/>
  </body>
</html>