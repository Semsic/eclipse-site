<?php
// ==================== CONFIGURAÇÃO ====================
header('Content-Type: application/json; charset=utf-8');

// Ficheiro de utilizadores
$usersFile = __DIR__ . '/users.json';

// ==================== FUNÇÕES AUXILIARES ====================
function jsonResponse($success, $message) {
    http_response_code($success ? 200 : 400);
    echo json_encode(['success' => $success, 'message' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

// ==================== SEGURANÇA BÁSICA ====================
// Só aceita POST para ações sensíveis (login, etc.)
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // Ação de teste é permitida via GET
    $action = $_GET['action'] ?? '';
    if ($action === 'test') {
        // Testa se o PHP está a funcionar e se o ficheiro existe
        if (!file_exists($usersFile)) {
            jsonResponse(false, 'users.json not found');
        }
        jsonResponse(true, 'API is alive. users.json ' . (is_writable($usersFile) ? 'is' : 'is NOT') . ' writable.');
    }
    jsonResponse(false, 'Only POST requests are allowed');
}

$action = $_POST['action'] ?? '';

// ==================== CARREGAR UTILIZADORES ====================
try {
    if (!file_exists($usersFile)) {
        file_put_contents($usersFile, json_encode(['users' => []], JSON_PRETTY_PRINT));
    }
    $jsonStr = file_get_contents($usersFile);
    if ($jsonStr === false) {
        throw new Exception('Could not read users file');
    }
    $data = json_decode($jsonStr, true);
    if ($data === null || !isset($data['users'])) {
        throw new Exception('users.json is malformed');
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Internal server error: ' . $e->getMessage()]);
    exit;
}

// ==================== AÇÃO DE LOGIN ====================
if ($action === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $hwid     = trim($_POST['hwid'] ?? '');

    if ($username === '') {
        jsonResponse(false, 'Username is empty');
    }
    if ($password === '') {
        jsonResponse(false, 'Password is empty');
    }

    // Procura o utilizador
    $userIndex = null;
    foreach ($data['users'] as $i => $user) {
        if ($user['username'] === $username) {
            $userIndex = $i;
            break;
        }
    }

    if ($userIndex === null) {
        jsonResponse(false, 'User not found');
    }

    $user = $data['users'][$userIndex];

    // Verifica se a hash está num formato válido
    if (substr($user['password_hash'], 0, 4) !== '$2y$' && substr($user['password_hash'], 0, 4) !== '$2a$') {
        // Se não for bcrypt, compara diretamente (apenas para migração)
        if ($password !== $user['password_hash']) {
            jsonResponse(false, 'Wrong password');
        } else {
            // Converte para bcrypt automaticamente
            $data['users'][$userIndex]['password_hash'] = password_hash($password, PASSWORD_BCRYPT);
            file_put_contents($usersFile, json_encode($data, JSON_PRETTY_PRINT));
        }
    } else {
        // Bcrypt normal
        if (!password_verify($password, $user['password_hash'])) {
            jsonResponse(false, 'Wrong password');
        }
    }

    // HWID
    if (empty($user['hwid'])) {
        // Primeiro login: guarda o HWID
        $data['users'][$userIndex]['hwid'] = $hwid;
        file_put_contents($usersFile, json_encode($data, JSON_PRETTY_PRINT));
    } elseif ($user['hwid'] !== $hwid) {
        jsonResponse(false, 'HWID mismatch');
    }

    // Sucesso
    jsonResponse(true, 'Login successful');
}

// ==================== AÇÃO DE RESET DE HWID (opcional) ====================
if ($action === 'resethwid') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        jsonResponse(false, 'Missing credentials');
    }

    // Procura o utilizador e verifica senha
    $userIndex = null;
    foreach ($data['users'] as $i => $user) {
        if ($user['username'] === $username) {
            $userIndex = $i;
            break;
        }
    }

    if ($userIndex === null) {
        jsonResponse(false, 'User not found');
    }

    $user = $data['users'][$userIndex];
    if (!password_verify($password, $user['password_hash'])) {
        jsonResponse(false, 'Wrong password');
    }

    // Limpa o HWID
    $data['users'][$userIndex]['hwid'] = '';
    file_put_contents($usersFile, json_encode($data, JSON_PRETTY_PRINT));
    jsonResponse(true, 'HWID reset successfully');
}

// ==================== RESPOSTA PADRÃO ====================
jsonResponse(false, 'Invalid action');