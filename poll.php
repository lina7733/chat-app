<?php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'Не авторизован']);
    exit;
}

$currentUserId = $_SESSION['user_id'];
$recipientId = isset($_GET['user_id']) ? (int)$_GET['user_id'] : null;

if ($recipientId) {
    $stmt = $pdo->prepare("
        SELECT m.id, m.message, u.username AS sender_username, m.created_at
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE (m.user_id = :current_user_id AND m.recipient_id = :recipient_id)
           OR (m.user_id = :recipient_id AND m.recipient_id = :current_user_id)
        ORDER BY m.created_at DESC
        LIMIT 1
    ");
    $stmt->execute([
        ':current_user_id' => $currentUserId,
        ':recipient_id' => $recipientId
    ]);
    $lastMessage = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode($lastMessage);
}
?>
