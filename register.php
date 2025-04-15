<?php
session_start();
include 'db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    // Проверка на существование пользователя
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->execute([':username' => $username]);
    
    if ($stmt->rowCount() > 0) {
        echo "Пользователь с таким именем уже существует.";
    } else {
        // Вставка нового пользователя
        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
        $stmt->execute([':username' => $username, ':password' => $password]);
        echo "Регистрация успешна! Теперь вы можете <a href='login.php'>войти</a>.";
    }
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Регистрация</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<h1>Регистрация</h1>
<form method="POST" action="">
    <input type="text" name="username" placeholder="Имя пользователя" required />
    <input type="password" name="password" placeholder="Пароль" required />
    <button type="submit">Зарегистрироваться</button>
</form>
<a href="login.php">Уже есть аккаунт? Войти</a>
</body>
</html>