<?php
    session_start();

    $user = $_REQUEST["user"];
    $pwd = $_REQUEST["pwd"];
    $hash = hash('sha256', $pwd);

   // echo "User: $user Password: $pwd";
     
//    if ($hash == "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92") {
//     echo "Привет, $user!";
//    }
//    else {
//         echo "Неверный логин или пароль";
//    }
//  1. Опасность sql injection
//
//


include("settings.php");

// $sql = "SELECT Login FROM Logins 
//         WHERE Login='$user' 
//         AND PwdHash='$hash'
//         ";

// //echo $sql;
$conn = mysqli_connect($DB_SERVER, $DB_USER, $DB_PWD, $DB_NAME);
// $result = mysqli_query($conn, $sql);
// $data = mysqli_fetch_assoc($result);

$sql = "SELECT Login FROM Logins 
         WHERE Login=? 
         AND PwdHash=?
        ";

$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "ss", $user, $hash);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$data = mysqli_fetch_assoc($result);

if (is_null($data)){
    echo "<h2>Bad user or password!";
    echo '<meta http-equiv="refresh" content="3, URL=login.php" > ';
}
else {
    echo("<h2>Hello, $user!</h2>");
    $_SESSION["user"] = $user;
    echo '<meta http-equiv="refresh" content="3, URL=home1.php" > ';

}


mysqli_close($conn);