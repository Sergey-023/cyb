<html>
	<head>
	<title>PHP</title>
	</head>
	<body>
		<h1>Привет от PHP!</h1>
		<?php
			$x = 2;
			$y = 2;
			$result = $x + $y;
			echo $result;
			
			$now = date("H:i:s");
			echo "<h2>Страница открыта в $now </h2>";
		?>
	</body>
</html>