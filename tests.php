<?php
require_once 'index.php';
require_once 'login.php';
require_once 'register.php';


// 1. Тест регистрации пользователя
function testUserRegistration() {
    $user = new User();
    $result = $user->register('testuser', 'password123');
    assertEqual($result['success'], true, 'Регистрация пользователя');
}


// 2. Тест отправки сообщения
function testSendMessage() {
    $message = new Message();
    $result = $message->send(1, 1, 'Привет!'); // chat_id, user_id, текст
    assertEqual($result['success'], true, 'Отправка сообщения');
}ssertEqual(is_array($messages), true, 'Получение списка сообщений');

// 3. Тест авторизации
function testUserLogin() {
    $user = new User();
    $result = $user->login('testuser', 'password123');
    assertEqual($result['success'], true, 'Авторизация пользователя');
}

// Запуск всех тестов
testUserRegistration();
testSendMessage();
testUserLogin();
