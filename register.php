<?php
// Запуск сессии
session_start();

// Генерация CSRF токена, если он не существует
if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(32));
}

// Подключение к базе данных
include("settings.php");
$link = mysqli_connect($DB_SERVER, $DB_USER, $DB_PWD, $DB_NAME);

// Обработка отправки формы
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Проверка CSRF
    if (!isset($_POST['token']) || !hash_equals($_SESSION['token'], $_POST['token'])) {
        die("CSRF validation failed.");
    }

    // Получение данных из формы
    $login = $_POST['login'];
    $PwdHash = $_POST['password'];

    // Проверка наличия логина в базе данных (избегаем дублирования) и защищаемся от SQL-инъекций
    $stmt = $link->prepare("SELECT * FROM Logins WHERE login = ?");
    $stmt->bind_param("s", $login);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if ($user) {
        echo "Этот логин уже занят, выберите другой.";
    } else {
        // Хеширование пароля
        $PwdHash = password_hash($PwdHash, PASSWORD_DEFAULT);

        // Добавление пользователя в базу данных
        $stmt = $link->prepare("INSERT INTO logins (login, PwdHash) VALUES (?, ?)");
        $stmt->bind_param("ss", $login, $PwdHash);
        $stmt->execute();

        echo "Регистрация прошла успешно!";
    }
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration</title>
</head>
<body>
    <h2>Регистрация</h2>
    <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
        <div>
            <label for="login">Логин:</label>
            <input type="text" id="login" name="login" required>
        </div>
        <div>
            <label for="password">Пароль:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <div>
            <input type="submit" value="Зарегистрироваться">
        </div>
    </form>
</body>
</html>