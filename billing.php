<?php
	session_start();
	if (!isset($_SESSION["user"])) {
		echo '<meta http-equiv="refresh" content="3, URL=login.php" > ';
		die("требуется логин! Вы будете перенаправлены через несколько секунд");
	}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Счет</title>
    <style>
        table {
            width: 300px;
            border: solid thin black;
        }

        tr:nth-child(even) {
            background-color: darkgray;
        }
    </style>
    <script>
        function getHistory() {
            var url = "api/billing_service.php";
            var xhr = new XMLHttpRequest();
            xhr.open("GET", url);
            xhr.onload = function() {
                //console.log(xhr.responseText);
                var data = JSON.parse(xhr.responseText);
                //console.log(data);
                var text = "<table>";
                for(var i=0; i < data.length; i++) {
                    //console.log(i);
                    var calc = data[i];
                    //console.log(calc);
                    var user = calc[0];
                    var timestamp = calc[1];
                    var result = calc[2];
                    //console.log(user, timestamp, result);
                    text += "<tr><td>" + user + 
                                "</td><td>" + timestamp + 
                                "</td><td> " + result + "</td></tr>";
                }
                text += "</table>";
                text += "<h3>С вас " + data.length * 1000 + " руб.</h3>";
                console.log(text);
                document.getElementById("display").innerHTML = text;
            }
            xhr.send();
        }

    </script>

</head>
<body onload="getHistory();">
    <h1>Ваш счет</h1>
    <div id="display">
    </div>
    
</body>
</html>