<?php
session_start();
include 'db.php';
//кэширование
$cacheFile = "cache/chat_{$currentUserId}_{$recipientId}.json";
$cacheTime = 60; // Время жизни кэша в секундах

if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheTime) {
    // Читаем данные из кэша
    $messages = json_decode(file_get_contents($cacheFile), true);
} else {
    // Загружаем данные из базы данных
    $stmt = $pdo->prepare("SELECT m.id, m.message, u.username AS sender_username, m.created_at 
        FROM messages m 
        JOIN users u ON m.user_id = u.id 
        WHERE (m.user_id = :current_user_id AND m.recipient_id = :recipient_id) 
           OR (m.user_id = :recipient_id AND m.recipient_id = :current_user_id) 
        ORDER BY m.created_at
    ");
    $stmt->execute([':current_user_id' => $currentUserId, ':recipient_id' => $recipientId]);
    $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Сохраняем в кэш
    file_put_contents($cacheFile, json_encode($messages));
}



//ролевая модель
function isLoggedIn() {
  return isset($_SESSION['user_id']);
}

function isAdmin() {
  return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function requireLogin() {
  if (!isLoggedIn()) {
      header('Location: login.php');
      exit;
  }
}

function requireRole($role) {
  if (!isset($_SESSION['role']) || $_SESSION['role'] !== $role) {
      http_response_code(403);
      echo "Access denied.";
      exit;
  }
}


// Проверка авторизации
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'Пользователь не авторизован']);
    exit;
}


// Генерация CSRF-токена
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Получение пользователей
$currentUserId = $_SESSION['user_id'];
$searchQuery = isset($_GET['search']) ? trim($_GET['search']) : ''; // Инициализация переменной
$sortOrder = isset($_GET['sort']) ? $_GET['sort'] : 'asc'; // Порядок сортировки

$stmt = $pdo->prepare("SELECT id, username FROM users WHERE id != :current_user_id AND username LIKE :search_query ORDER BY username " . strtoupper($sortOrder));
$stmt->execute([':current_user_id' => $currentUserId, ':search_query' => '%' . $searchQuery . '%']);
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Инициализация переменной $chatName
$chatName = '';
// Получение сообщений и названия чата для выбранного пользователя
$recipientId = isset($_GET['user_id']) ? (int)$_GET['user_id'] : null;
if ($recipientId) {
  // Получаем название чата
  $stmt = $pdo->prepare("SELECT chat_name 
  FROM chats 
  WHERE (user1_id = :current_user_id AND user2_id = :recipient_id) 
     OR (user1_id = :recipient_id AND user2_id = :current_user_id)
");
$stmt->execute([':current_user_id' => $currentUserId, ':recipient_id' => $recipientId]);
  if ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
      $chatName = $row['chat_name'];
      $chatId = $stmt->fetchColumn();
  } else {
      // Если чат не найден, можно задать значение по умолчанию
      // Здесь мы используем username полученного пользователя для создания имени чата
      foreach ($users as $user) {
          if ($user['id'] == $recipientId) {
              $chatName = "Чат с " . htmlspecialchars($user['username']);
              break;
          }
      }
  }}


if ($recipientId) {
    $stmt = $pdo->prepare("SELECT m.id, m.message, u.username AS sender_username, m.created_at 
        FROM messages m 
        JOIN users u ON m.user_id = u.id 
        WHERE (m.user_id = :current_user_id AND m.recipient_id = :recipient_id) 
           OR (m.user_id = :recipient_id AND m.recipient_id = :current_user_id) 
        ORDER BY m.created_at
    ");
    $stmt->execute([':current_user_id' => $currentUserId, ':recipient_id' => $recipientId]);
    $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
} else {
    $messages = [];
}

// Обработка отправки сообщения
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['message']) && !empty($_POST['recipient_id'])) {
    // Проверка CSRF-токена
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        echo json_encode(['error' => 'Неверный CSRF-токен']);
        exit;
    }

    $message = $_POST['message'];
    $recipientId = $_POST['recipient_id'];

    // Проверка существования получателя
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE id = :recipient_id");
    $stmt->execute([':recipient_id' => $recipientId]);
    
    if ($stmt->fetchColumn() == 0) {
        echo json_encode(['error' => 'Получатель не найден']);
        exit;
    }

    // Сохранение сообщения в базе данных
    $stmt = $pdo->prepare("INSERT INTO messages (message, user_id, recipient_id) VALUES (:message, :user_id, :recipient_id)");

    if ($stmt->execute([':message' => $message, ':user_id' => $currentUserId, ':recipient_id' => $recipientId])) {
        echo json_encode(['message' => htmlspecialchars($message), 'created_at' => date('Y-m-d H:i:s')]);
    } else {
        echo json_encode(['error' => 'Не удалось сохранить сообщение']);
    }
    exit;
}

// Обработка удаления сообщения
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_message']) && isset($_POST['message_id'])) {
    // Проверка CSRF-токена
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        echo json_encode(['error' => 'Неверный CSRF-токен']);
        exit;
    }

    // Удаление сообщения из базы данных
    $messageId = $_POST['message_id'];
    
    // Проверка прав на удаление сообщения (пользователь должен быть либо отправителем, либо получателем)
    $stmt = $pdo->prepare("DELETE FROM messages WHERE id = :id AND (user_id = :user OR recipient_id = :user)");
    
    if ($stmt->execute([':id' => $messageId, ':user' => $currentUserId])) {
        echo json_encode(['success' => 'Сообщение успешно удалено!']);
        exit;
    } else {
        echo json_encode(['error' => 'Не удалось удалить сообщение']);
        exit;
    }
}

// Обработка изменения названия чата
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['chat_name']) && isset($_POST['chat_id'])) {
    // Проверка CSRF-токена
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        echo json_encode(['error' => 'Неверный CSRF-токен']);
        exit;
    }

    // Обновление названия чата в базе данных
    $chatName = $_POST['chat_name'];
    $chatId = $_POST['chat_id'];

   // Обновление названия чата в базе данных
   $stmt = $pdo->prepare("UPDATE chats SET chat_name = ? WHERE id = ?");
    
   if ($stmt->execute([$chatName, $chatId])) {
       echo json_encode(['success' => 'Название чата успешно обновлено!']);
       exit;
   } else {
       echo json_encode(['error' => 'Не удалось обновить название чата']);
       exit;
   }
}
//валидация бекенд
// Пример обработки отправки сообщения
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sendMessage'])) {
  $message = trim($_POST['message']);
  
  // Проверка на пустое сообщение
  if (empty($message)) {
      echo json_encode(['error' => 'Сообщение не может быть пустым!']);
      exit;
  }

  // Дополнительные проверки, например, длина сообщения
  if (strlen($message) > 255) {
      echo json_encode(['error' => 'Сообщение не должно превышать 255 символов!']);
      exit;
  }

  // Здесь код для сохранения сообщения в базу данных...
}

// Пример обработки изменения названия чата
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['changeChatName'])) {
  $chatName = trim($_POST['chat_name']);

  // Проверка на пустое название чата
  if (empty($chatName)) {
      echo json_encode(['error' => 'Название чата не может быть пустым!']);
      exit;
  }

  // Дополнительные проверки, например, длина названия чата
  if (strlen($chatName) > 50) {
      echo json_encode(['error' => 'Название чата не должно превышать 50 символов!']);
      exit;
  }

  // Здесь код для обновления названия чата в базе данных...
}


?>

<!DOCTYPE html>
<html lang="ru">
<head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title>Чат</title>
   <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    
<!-- Сторона пользователей -->
<div class="sidebar">
<h2>Пользователи</h2>
<!-- Форма поиска -->
<form method="GET" action="">
    <input type="text" name="search" placeholder="Поиск по имени..." value="<?= htmlspecialchars($searchQuery) ?>">
    <button type="submit">Поиск</button>

    <!-- Выпадающий список для сортировки -->
    <select name="sort">
        <option value="asc" <?= ($sortOrder === 'asc') ? 'selected' : '' ?>>По возрастанию</option>
        <option value="desc" <?= ($sortOrder === 'desc') ? 'selected' : '' ?>>По убыванию</option>
    </select>
    
    <button type="submit">Применить</button>

    
</form>
<ul>
<?php if (!empty($users)): ?>
<?php foreach ($users as $user): ?>
<li><a href="?user_id=<?= htmlspecialchars($user['id']) ?>"><?= htmlspecialchars($user['username']) ?></a></li>
<?php endforeach; ?>
<?php else: ?>
<li>Нет пользователей</li>
<?php endif; ?>
</ul>
<!-- Кнопка выхода -->
<form action="logout.php" method="POST">
<button type="submit">Выйти</button>
</form>
</div>

<!-- Окно чата -->
<div class="chat-window">
<h2><?htmlspecialchars($chatName)?> с <?= isset($recipientId) ? htmlspecialchars($users[array_search($recipientId, array_column($users, 'id'))]['username']) : 'выберите пользователя' ?></h2>

<!-- Отображение сообщений -->
<div class="messages">
<?php if (!empty($messages)): ?>
<?php foreach ($messages as $message): ?>
<div class="message" data-id="<?= htmlspecialchars($message['id']) ?>">
<strong><?= htmlspecialchars($message['sender_username']) ?>:</strong> <?= htmlspecialchars($message['message']) ?> <em>(<?= htmlspecialchars($message['created_at']) ?>)</em>
<button class="delete-message">Удалить</button>
</div>
<?php endforeach; ?>
<?php else: ?>
<div>Нет сообщений</div>
<?php endif; ?>
</div>

<!-- Форма отправки сообщения -->
 <div class='chat-container'>
 <div class="message-input">
<form id="messageForm" method="POST" action="">
  
<input type="text" id="message" name="message" placeholder="Введите сообщение..." required>
<button id="emoji-button">😊</button>
</div>
<input type="hidden" name="recipient_id" value="<?= isset($recipientId) ? htmlspecialchars($recipientId) : '' ?>">
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
<button type="submit">Отправить</button>
<div class="emoji-panel" id="emoji-panel">
        <span class="emoji" data-emoji="😀">😀</span>
        <span class="emoji" data-emoji="😁">😁</span>
        <span class="emoji" data-emoji="😂">😂</span>
        <span class="emoji" data-emoji="😃">😃</span>
        <span class="emoji" data-emoji="😄">😄</span>
        <span class="emoji" data-emoji="😅">😅</span>
        <span class="emoji" data-emoji="😆">😆</span>
        <span class="emoji" data-emoji="😉">😉</span>
        <span class="emoji" data-emoji="😊">😊</span>
        <span class="emoji" data-emoji="😋">😋</span>
        <!-- Добавьте больше эмодзи по желанию -->
    </div>
    <div id="messages"></div>
</div>
</form>

<!-- Форма изменения названия чата -->
<form id="chatNameForm" method="POST" action="">
<label for="chat_name">Название чата:</label>
<input type="text" name="chat_name" value="<?= isset($chatName) ? htmlspecialchars($chatName) : '' ?>" required>
<input type="hidden" name="chat_id" value="<?= isset($chatId) ? htmlspecialchars($chatId) : '' ?>">
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
<button type="submit">Изменить название</button>
</form>



</div>
</div>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script>
// AJAX для отправки сообщения
$(document).ready(function() {
$('#messageForm').on('submit', function(e) {
e.preventDefault(); // Предотвращаем перезагрузку

$.ajax({
type: 'POST',
url: '', // текущая страница
data: $(this).serialize(),
dataType: 'json', // ОЖИДАЕМ JSON ОТ СЕРВЕРА!
success: function(response) {
if (response.message) {
$('input[name="message"]').val('');
$('.messages').append('<div class="message"><strong>Вы:</strong> ' + response.message + '</div>');
$('.messages').scrollTop($('.messages')[0].scrollHeight);
} else if (response.error) {
alert(response.error);
}
},
error: function(xhr, status, error) {
console.error('Ошибка AJAX:', status, error);
alert('Произошла ошибка при отправке сообщения.');
}
});
});

// AJAX для удаления сообщения
$(document).on('click', '.delete-message', function() {
var messageElement = $(this).closest('.message');
var messageId = messageElement.data('id');

$.ajax({
type: 'POST',
url: '', // текущая страница
data: { delete_message: true, message_id: messageId, csrf_token: $('input[name=csrf_token]').val() },
dataType: 'json',
success: function(response) {
if (response.success) {
alert(response.success);
messageElement.remove();
} else if (response.error) {
alert(response.error);
}
},
error: function(xhr, status, error) {
console.error('Ошибка AJAX:', status, error);
alert('Произошла ошибка при удалении сообщения.');
}
});
});

// AJAX для изменения названия чата
$('#chatNameForm').on('submit', function(e) {
e.preventDefault(); // Предотвращаем перезагрузку

$.ajax({
type: 'POST',
url: '', // текущая страница
data: $(this).serialize(),
dataType: 'json', // ОЖИДАЕМ JSON ОТ СЕРВЕРА!
success: function(response) {
if (response.success) {
alert(response.success);
} else if (response.error) {
alert(response.error);
}
},
error: function(xhr, status, error) {
console.error('Ошибка AJAX:', status, error);
alert('Произошла ошибка при изменении названия чата.');
}
});
});
});
$(document).ready(function() {
    // Валидация формы отправки сообщения
    $('#sendMessageForm').on('submit', function(e) {
        var message = $('#messageInput').val().trim();
        if (message === '') {
            e.preventDefault(); // Отменяем отправку формы
            alert('Сообщение не может быть пустым!');
        }
    });

    // Валидация формы изменения названия чата
    $('#changeChatNameForm').on('submit', function(e) {
        var chatName = $('#chatNameInput').val().trim();
        if (chatName === '') {
            e.preventDefault(); // Отменяем отправку формы
            alert('Название чата не может быть пустым!');
        }
    });
});

const emojiButton = document.getElementById('emoji-button');
const emojiPanel = document.getElementById('emoji-panel');
const messageInput = document.getElementById('message');
const sendButton = document.getElementById('send-button');
const messagesContainer = document.getElementById('messages');

// Показать/скрыть панель эмодзи
emojiButton.addEventListener('click', () => {
   emojiPanel.style.display = emojiPanel.style.display === 'block' ? 'none' : 'block';
});

// Вставить выбранный эмодзи в текстовое поле
document.querySelectorAll('.emoji').forEach(emoji => {
   emoji.addEventListener('click', () => {
       const selectedEmoji = emoji.getAttribute('data-emoji');
       messageInput.value += selectedEmoji; // Добавляем эмодзи в текстовое поле
       emojiPanel.style.display = 'none'; // Скрываем панель после выбора
   });
});

// Отправка сообщения
sendButton.addEventListener('click', () => {
   const messageText = messageInput.value.trim();
   if (messageText) {
       const messageElement = document.createElement('div');
       messageElement.textContent = messageText; // Отображаем текст сообщения
       messagesContainer.appendChild(messageElement); // Добавляем сообщение в контейнер
       messageInput.value = ''; // Очищаем поле ввода
   }
});

// Закрыть панель при клике вне ее
document.addEventListener('click', (event) => {
   if (!event.target.closest('.chat-container')) {
       emojiPanel.style.display = 'none';
   }
});

//веб сокет


let lastMessageId = null;

function pollNewMessages() {
    const recipientId = "<?= $recipientId ?>";
    if (!recipientId) return;

    fetch('poll.php?user_id=' + recipientId)
        .then(response => response.json())
        .then(data => {
            if (data && data.id && data.id !== lastMessageId) {
                lastMessageId = data.id;
                const messageHtml = `
                    <div class="message" data-id="${data.id}">
                        <strong>${data.sender_username}:</strong> ${data.message}
                        <em>(${data.created_at})</em>
                        <button class="delete-message">Удалить</button>
                    </div>`;
                document.querySelector('.messages').insertAdjacentHTML('beforeend', messageHtml);
            }
        })
        .catch(error => {
            console.error('Ошибка при получении новых сообщений:', error);
        })
        .finally(() => {
            setTimeout(pollNewMessages, 3000); // Запрос каждые 3 секунды
        });
}

// Запускаем polling при загрузке
document.addEventListener('DOMContentLoaded', pollNewMessages);


</script>

</body>
</html>