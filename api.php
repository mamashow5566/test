<?php
// Simple RESTful API for user registration and password reset
// No framework or OOP - just functions

$db = new SQLite3(__DIR__ . '/users.db');
init_db($db);

$request_method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Route requests
if ($path === '/register' && $request_method === 'POST') {
    register_user($db);
} elseif ($path === '/verify' && $request_method === 'GET') {
    verify_email($db);
} elseif ($path === '/forgot-password' && $request_method === 'POST') {
    forgot_password($db);
} elseif ($path === '/reset-password' && $request_method === 'POST') {
    reset_password($db);
} else {
    http_response_code(404);
    echo json_encode(['error' => 'Not found']);
}

function init_db($db) {
    $db->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT UNIQUE,
        password_hash TEXT,
        email TEXT,
        phone TEXT,
        nickname TEXT,
        verification_code TEXT,
        is_verified INTEGER DEFAULT 0,
        reset_code TEXT
    )');
}

function get_input() {
    return json_decode(file_get_contents('php://input'), true);
}

function valid_account($account) {
    return filter_var($account, FILTER_VALIDATE_EMAIL) ||
           preg_match('/^\d{10,}$/', $account) ||
           preg_match('/^[a-zA-Z0-9]+$/', $account);
}

function valid_password($password) {
    return preg_match('/^[a-zA-Z0-9]{10,}$/', $password);
}

function register_user($db) {
    $data = get_input();
    if (!isset($data['account']) || !isset($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing fields']);
        return;
    }
    $account = $data['account'];
    $password = $data['password'];
    if (!valid_account($account) || !valid_password($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid account or password']);
        return;
    }
    $verification_code = bin2hex(random_bytes(16));
    $password_hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare('INSERT INTO users (account, password_hash, email, phone, nickname, verification_code) VALUES (:account, :password_hash, :email, :phone, :nickname, :verification_code)');
    $email = filter_var($account, FILTER_VALIDATE_EMAIL) ? $account : ($data['email'] ?? null);
    $phone = preg_match('/^\d{10,}$/', $account) ? $account : ($data['phone'] ?? null);
    $nickname = preg_match('/^[a-zA-Z0-9]+$/', $account) ? $account : ($data['nickname'] ?? null);
    $stmt->bindValue(':account', $account, SQLITE3_TEXT);
    $stmt->bindValue(':password_hash', $password_hash, SQLITE3_TEXT);
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $stmt->bindValue(':phone', $phone, SQLITE3_TEXT);
    $stmt->bindValue(':nickname', $nickname, SQLITE3_TEXT);
    $stmt->bindValue(':verification_code', $verification_code, SQLITE3_TEXT);
    if ($stmt->execute()) {
        send_verification_email($email, $verification_code);
        echo json_encode(['status' => 'ok']);
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Account already exists']);
    }
}

function send_verification_email($email, $code) {
    if (!$email) return;
    $subject = 'Verify your account';
    $link = 'http://' . $_SERVER['HTTP_HOST'] . '/verify?code=' . urlencode($code);
    $message = "Click the link to verify your account: $link";
    mail($email, $subject, $message);
}

function verify_email($db) {
    if (!isset($_GET['code'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing code']);
        return;
    }
    $code = $_GET['code'];
    $stmt = $db->prepare('UPDATE users SET is_verified = 1 WHERE verification_code = :code');
    $stmt->bindValue(':code', $code, SQLITE3_TEXT);
    if ($stmt->execute() && $db->changes()) {
        echo json_encode(['status' => 'verified']);
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid code']);
    }
}

function forgot_password($db) {
    $data = get_input();
    if (!isset($data['account'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing account']);
        return;
    }
    $account = $data['account'];
    $reset_code = bin2hex(random_bytes(16));
    $stmt = $db->prepare('UPDATE users SET reset_code = :reset_code WHERE account = :account');
    $stmt->bindValue(':reset_code', $reset_code, SQLITE3_TEXT);
    $stmt->bindValue(':account', $account, SQLITE3_TEXT);
    if ($stmt->execute() && $db->changes()) {
        $user = $db->querySingle('SELECT email FROM users WHERE account = ' . $db->escapeString($account), true);
        if ($user && $user['email']) {
            $subject = 'Password reset';
            $link = 'http://' . $_SERVER['HTTP_HOST'] . '/reset-password?code=' . urlencode($reset_code);
            $message = "Click the link to reset your password: $link";
            mail($user['email'], $subject, $message);
        }
        echo json_encode(['status' => 'ok']);
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Account not found']);
    }
}

function reset_password($db) {
    $data = get_input();
    if (!isset($data['code']) || !isset($data['new_password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing fields']);
        return;
    }
    $code = $data['code'];
    $new_password = $data['new_password'];
    if (!valid_password($new_password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid password']);
        return;
    }
    $new_hash = password_hash($new_password, PASSWORD_DEFAULT);
    $stmt = $db->prepare('UPDATE users SET password_hash = :hash, reset_code = NULL WHERE reset_code = :code');
    $stmt->bindValue(':hash', $new_hash, SQLITE3_TEXT);
    $stmt->bindValue(':code', $code, SQLITE3_TEXT);
    if ($stmt->execute() && $db->changes()) {
        echo json_encode(['status' => 'password reset']);
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid code']);
    }
}
