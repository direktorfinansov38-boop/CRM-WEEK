<?php
// ═══════════════════════════════════════════════
//  Kimchi CRM — API v3 (исправленная версия)
//  Исправлено: CSRF, rate limiting, явная auth,
//  нет утечки логинов, валидация inputs
// ═══════════════════════════════════════════════

ini_set('display_errors', 0);
error_reporting(E_ALL);

session_start();
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate');

require_once __DIR__ . '/config.php';

// ── Helpers ────────────────────────────────────
function ok($data = [])  {
    echo json_encode(['ok' => true, 'data' => $data], JSON_UNESCAPED_UNICODE);
    exit;
}
function err($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

// ── DB ─────────────────────────────────────────
function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    try {
        $pdo = new PDO(
            'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
            DB_USER, DB_PASS,
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]
        );
    } catch (Exception $e) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' => 'Ошибка подключения к базе данных']);
        exit;
    }
    return $pdo;
}

// ── CSRF ────────────────────────────────────────
function getCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrf(): void {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN']
          ?? getallheaders()['X-Csrf-Token']
          ?? '';
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        err('Неверный CSRF-токен', 403);
    }
}

// ── Rate limiting (login) ───────────────────────
function checkRateLimit(string $login, string $ip): void {
    $db = db();
    // Очищаем старые записи
    $db->prepare('DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 15 MINUTE)')->execute();
    // Считаем попытки
    $st = $db->prepare('SELECT COUNT(*) FROM login_attempts WHERE (login=? OR ip=?) AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)');
    $st->execute([$login, $ip]);
    if ((int)$st->fetchColumn() >= 10) {
        err('Слишком много попыток входа. Подождите 15 минут.', 429);
    }
}
function recordFailedAttempt(string $login, string $ip): void {
    db()->prepare('INSERT INTO login_attempts(login, ip) VALUES(?,?)')->execute([$login, $ip]);
}
function clearAttempts(string $login, string $ip): void {
    db()->prepare('DELETE FROM login_attempts WHERE login=? OR ip=?')->execute([$login, $ip]);
}
function getClientIp(): string {
    return $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? '0.0.0.0';
}

// ── Auth ────────────────────────────────────────
function requireAuth(): void {
    if (empty($_SESSION['user_id'])) err('Не авторизован', 401);
}

function currentUser(): array {
    requireAuth();
    $st = db()->prepare('SELECT * FROM users WHERE id=? AND active=1');
    $st->execute([$_SESSION['user_id']]);
    $u = $st->fetch();
    if (!$u) {
        session_destroy();
        err('Сессия истекла', 401);
    }
    return $u;
}

function isAdmin(array $u): bool {
    return $u['role'] === 'Администратор';
}

// ── Validate plan key ───────────────────────────
function isValidPlanKey(string $key): bool {
    return (bool) preg_match('/^[a-zA-Zа-яёА-ЯЁ0-9_\-\.]{1,200}$/u', $key);
}

// ── Router ──────────────────────────────────────
$action = $_GET['action'] ?? '';
$body   = json_decode(file_get_contents('php://input'), true) ?? [];

// CSRF-токен выдаётся без проверки (GET)
if ($action === 'csrf') {
    ok(['token' => getCsrfToken()]);
}

// Методы изменяющие данные — проверяем CSRF
$writeMethods = [
    'login','logout','users.save','users.delete',
    'entries.save','entries.delete','plan.save','plan.reset'
];
if (in_array($action, $writeMethods, true)) {
    verifyCsrf();
}

switch ($action) {

    // ── Публичные ─────────────────────────────────

    case 'login':
        $login = strtolower(trim($body['login'] ?? ''));
        $pass  = (string)($body['password'] ?? '');
        $ip    = getClientIp();
        if (!$login || !$pass) err('Введите логин и пароль');

        checkRateLimit($login, $ip);

        $st = db()->prepare('SELECT * FROM users WHERE login=? AND active=1');
        $st->execute([$login]);
        $u = $st->fetch();

        // Одинаковое время ответа при неверном логине и пароле
        $fakeHash = '$2y$12$invalidhashinvalidhashinvalidhas';
        $hash = $u ? $u['password_hash'] : $fakeHash;

        if (!$u || !password_verify($pass, $hash)) {
            recordFailedAttempt($login, $ip);
            err('Неверный логин или пароль');
        }

        clearAttempts($login, $ip);
        session_regenerate_id(true);
        $_SESSION['user_id'] = $u['id'];
        // Новый CSRF при входе
        unset($_SESSION['csrf_token']);

        unset($u['password_hash']);
        $u['accessPts'] = json_decode($u['access_pts'] ?? '[]', true);
        $u['csrfToken'] = getCsrfToken();
        ok($u);

    case 'logout':
        requireAuth();
        session_destroy();
        ok();

    case 'me':
        requireAuth();
        $u = currentUser();
        unset($u['password_hash']);
        $u['accessPts'] = json_decode($u['access_pts'] ?? '[]', true);
        $u['csrfToken'] = getCsrfToken();
        ok($u);

    // Только имена+роли — логин НЕ возвращается
    case 'users.public':
        $rows = db()->query(
            'SELECT id, name, role, color, ini, pt FROM users WHERE active=1 ORDER BY role DESC, name'
        )->fetchAll();
        ok($rows);

    // ── Авторизованные ────────────────────────────

    case 'users.list':
        requireAuth();
        $me = currentUser();
        if (!isAdmin($me)) err('Нет доступа', 403);
        $rows = db()->query(
            'SELECT id,name,login,role,color,ini,pt,access_pts,active FROM users ORDER BY role DESC, name'
        )->fetchAll();
        foreach ($rows as &$r) $r['accessPts'] = json_decode($r['access_pts'] ?? '[]', true);
        ok($rows);

    case 'users.save':
        requireAuth();
        $me = currentUser();
        if (!isAdmin($me)) err('Нет доступа', 403);

        $id        = $body['id']       ?? null;
        $name      = trim($body['name']  ?? '');
        $login     = strtolower(trim($body['login'] ?? ''));
        $role      = in_array($body['role'] ?? '', ['Администратор','Управляющий'], true)
                        ? $body['role'] : 'Управляющий';
        $color     = preg_match('/^#[0-9a-fA-F]{6}$/', $body['color'] ?? '') ? $body['color'] : '#a78bfa';
        $ini       = mb_strtoupper(mb_substr(trim($body['ini'] ?? mb_substr($name, 0, 3)), 0, 5));
        $pt        = trim($body['pt'] ?? '');
        $accessPts = json_encode(array_filter((array)($body['accessPts'] ?? []), 'is_string'));
        $newPass   = $body['password'] ?? null;

        if (!$name || !$login) err('Имя и логин обязательны');
        if (!preg_match('/^[a-z0-9_]{3,60}$/', $login)) err('Логин: только a-z, 0-9, _ (3–60 символов)');

        if ($id) {
            // Нельзя понизить себя
            if ($id === $me['id'] && $role !== 'Администратор') err('Нельзя сменить свою роль');
            if ($newPass) {
                if (strlen($newPass) < 6) err('Пароль минимум 6 символов');
                $hash = password_hash($newPass, PASSWORD_BCRYPT, ['cost' => 12]);
                db()->prepare('UPDATE users SET name=?,login=?,role=?,color=?,ini=?,pt=?,access_pts=?,password_hash=? WHERE id=?')
                   ->execute([$name,$login,$role,$color,$ini,$pt,$accessPts,$hash,$id]);
            } else {
                db()->prepare('UPDATE users SET name=?,login=?,role=?,color=?,ini=?,pt=?,access_pts=? WHERE id=?')
                   ->execute([$name,$login,$role,$color,$ini,$pt,$accessPts,$id]);
            }
            ok(['id' => $id]);
        } else {
            if (!$newPass || strlen($newPass) < 6) err('Пароль обязателен (минимум 6 символов)');
            // Проверка на дублирующийся логин
            $dup = db()->prepare('SELECT id FROM users WHERE login=?');
            $dup->execute([$login]);
            if ($dup->fetch()) err('Логин уже занят');

            $hash  = password_hash($newPass, PASSWORD_BCRYPT, ['cost' => 12]);
            $newId = 'u_' . bin2hex(random_bytes(8));
            db()->prepare('INSERT INTO users(id,name,login,role,color,ini,pt,access_pts,password_hash,active) VALUES(?,?,?,?,?,?,?,?,?,1)')
               ->execute([$newId,$name,$login,$role,$color,$ini,$pt,$accessPts,$hash]);
            ok(['id' => $newId]);
        }

    case 'users.delete':
        requireAuth();
        $me = currentUser();
        if (!isAdmin($me)) err('Нет доступа', 403);
        $id = $body['id'] ?? '';
        if (!$id) err('id обязателен');
        if ($id === $me['id']) err('Нельзя удалить себя');
        db()->prepare('UPDATE users SET active=0 WHERE id=?')->execute([$id]);
        ok();

    case 'entries.load':
        requireAuth();
        $u = currentUser();
        if (isAdmin($u)) {
            $rows = db()->query('SELECT * FROM entries WHERE deleted=0 ORDER BY created_at DESC')->fetchAll();
        } else {
            $pts = json_decode($u['access_pts'] ?? '[]', true);
            $pts[] = $u['pt'];
            $pts = array_values(array_unique(array_filter($pts, 'is_string')));
            if (!$pts) ok([]);
            $ph = implode(',', array_fill(0, count($pts), '?'));
            $st = db()->prepare("SELECT * FROM entries WHERE deleted=0 AND pt IN ($ph) ORDER BY created_at DESC");
            $st->execute($pts);
            $rows = $st->fetchAll();
        }
        foreach ($rows as &$r) $r['data'] = json_decode($r['data'] ?? '{}', true);
        ok($rows);

    case 'entries.save':
        requireAuth();
        $u       = currentUser();
        $entries = $body['entries'] ?? [];
        if (!is_array($entries)) err('Неверный формат');

        $myPts = isAdmin($u) ? null : array_unique(array_filter(
            array_merge(json_decode($u['access_pts'] ?? '[]', true), [$u['pt']]),
            'is_string'
        ));

        $pdo = db();
        $pdo->beginTransaction();
        try {
            $st = $pdo->prepare(
                'INSERT INTO entries(id,pt,week_num,user_id,data,created_at,updated_at,deleted)
                 VALUES(?,?,?,?,?,NOW(),NOW(),0)
                 ON DUPLICATE KEY UPDATE data=VALUES(data), updated_at=NOW(), deleted=0'
            );
            foreach ($entries as $e) {
                $eid  = (string)($e['id']  ?? '');
                $pt   = (string)($e['pt']  ?? '');
                $wn   = (int)   ($e['wn']  ?? 0);
                if (!$eid || !$pt) continue;
                if ($myPts !== null && !in_array($pt, $myPts, true)) continue;
                $st->execute([$eid, $pt, $wn, $u['id'], json_encode($e, JSON_UNESCAPED_UNICODE)]);
            }
            $pdo->commit();
            ok();
        } catch (Exception $ex) {
            $pdo->rollBack();
            err('Ошибка сохранения: ' . $ex->getMessage());
        }

    case 'entries.delete':
        requireAuth();
        $u   = currentUser();
        $eid = $body['id'] ?? '';
        if (!$eid) err('id обязателен');
        if (!isAdmin($u)) {
            $st = db()->prepare('SELECT user_id FROM entries WHERE id=? AND deleted=0');
            $st->execute([$eid]);
            $row = $st->fetch();
            if (!$row || $row['user_id'] !== $u['id']) err('Нет доступа', 403);
        }
        db()->prepare('UPDATE entries SET deleted=1 WHERE id=?')->execute([$eid]);
        ok();

    case 'plan.load':
        requireAuth();
        $rows = db()->query('SELECT * FROM plan_edits')->fetchAll();
        $result = [];
        foreach ($rows as $r) $result[$r['key_name']] = (float)$r['value'];
        ok($result);

    case 'plan.save':
        requireAuth();
        $me = currentUser();
        if (!isAdmin($me)) err('Нет доступа', 403);
        $edits = $body['edits'] ?? [];
        if (!is_array($edits)) err('Неверный формат');

        $pdo = db();
        $pdo->beginTransaction();
        try {
            $st = $pdo->prepare(
                'INSERT INTO plan_edits(key_name,value,updated_by,updated_at) VALUES(?,?,?,NOW())
                 ON DUPLICATE KEY UPDATE value=VALUES(value), updated_by=VALUES(updated_by), updated_at=NOW()'
            );
            foreach ($edits as $key => $val) {
                if (!isValidPlanKey((string)$key)) continue;
                $st->execute([(string)$key, (float)$val, $me['id']]);
            }
            $pdo->commit();
            ok();
        } catch (Exception $ex) {
            $pdo->rollBack();
            err('Ошибка: ' . $ex->getMessage());
        }

    case 'plan.reset':
        requireAuth();
        $me = currentUser();
        if (!isAdmin($me)) err('Нет доступа', 403);
        db()->exec('DELETE FROM plan_edits');
        ok();

    case 'ping':
        ok(['time' => date('c'), 'auth' => !empty($_SESSION['user_id'])]);

    default:
        err('Неизвестный action', 404);
}
