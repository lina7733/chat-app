<?php
$host = 'localhost';
$db = 'chat_app';
$user = 'root'; // Замените на ваше имя пользователя MySQL
$pass = ''; // Замените на ваш пароль MySQL

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Ошибка подключения: " . $e->getMessage();
}
?>