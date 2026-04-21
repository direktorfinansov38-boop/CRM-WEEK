<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kimchi CRM — Установщик</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0b0e14;color:#dce1f0;max-width:640px;margin:40px auto;padding:20px}
  h1{color:#a78bfa;margin-bottom:8px}
  .card{background:rgba(20,26,40,.9);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:24px;margin:16px 0}
  .ok{color:#4ade80;font-weight:700}
  .err{color:#f87171;font-weight:700}
  pre{background:rgba(0,0,0,.4);padding:12px;border-radius:8px;font-size:13px;overflow-x:auto;white-space:pre-wrap}
  .btn{display:inline-block;padding:10px 24px;border-radius:8px;background:#a78bfa;color:#fff;font-weight:700;cursor:pointer;border:none;font-size:15px;text-decoration:none}
  .btn:hover{background:#9061f9}
  input{width:100%;padding:8px 12px;border-radius:8px;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.05);color:#fff;font-size:14px;box-sizing:border-box;margin:4px 0 12px}
  label{font-size:13px;color:rgba(200,210,235,.7)}
  .step{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:14px}
  .dot{width:20px;height:20px;border-radius:50%;background:rgba(255,255,255,.08);display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0}
  .dot.ok{background:#4ade80;color:#000}.dot.err{background:#f87171;color:#000}
</style>
</head>
<body>
<h1>🍜 Kimchi CRM — Установщик</h1>

<?php
require_once __DIR__ . '/config.php';

// ── Защита токеном ──────────────────────────────
$token = INSTALL_TOKEN;
$provided = $_GET['token'] ?? $_POST['token'] ?? '';

if (empty($token)) {
    // Токен не задан в .env — блокируем доступ
    http_response_code(403);
    echo '<div class="card"><p class="err">⛔ Доступ запрещён.</p>';
    echo '<p style="font-size:13px;color:rgba(200,210,235,.6)">Добавьте <code>INSTALL_TOKEN=ваш_секретный_токен</code> в файл <code>.env</code>,<br>затем откройте <code>install.php?token=ваш_секретный_токен</code></p></div>';
    exit;
}

if ($provided !== $token) {
    http_response_code(403);
    echo '<div class="card"><p class="err">⛔ Неверный токен доступа.</p></div>';
    exit;
}
// ────────────────────────────────────────────────

$steps  = [];
$errors = [];

function step($ok, $msg) {
    global $steps, $errors;
    $steps[] = ['ok' => $ok, 'msg' => $msg];
    if (!$ok) $errors[] = $msg;
}

try {
    $pdo = new PDO('mysql:host='.DB_HOST.';charset=utf8mb4', DB_USER, DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    step(true, 'Подключение к MySQL: OK');
} catch (Exception $e) {
    step(false, 'Подключение к MySQL: ОШИБКА — ' . $e->getMessage());
    $pdo = null;
}

if ($pdo && !$errors) {
    try {
        $pdo->exec('CREATE DATABASE IF NOT EXISTS `'.DB_NAME.'` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
        $pdo->exec('USE `'.DB_NAME.'`');
        step(true, 'База данных `'.DB_NAME.'`: OK');
    } catch (Exception $e) {
        step(false, 'Создание БД: ' . $e->getMessage());
    }

    $tables = [
        'users' => "CREATE TABLE IF NOT EXISTS `users` (
            `id`            VARCHAR(40)  NOT NULL PRIMARY KEY,
            `name`          VARCHAR(100) NOT NULL,
            `login`         VARCHAR(60)  NOT NULL UNIQUE,
            `password_hash` VARCHAR(255) NOT NULL,
            `role`          ENUM('Администратор','Управляющий') NOT NULL DEFAULT 'Управляющий',
            `color`         VARCHAR(20)  NOT NULL DEFAULT '#a78bfa',
            `ini`           VARCHAR(10)  NOT NULL DEFAULT '',
            `pt`            VARCHAR(100) NOT NULL DEFAULT '',
            `access_pts`    TEXT,
            `active`        TINYINT(1)   NOT NULL DEFAULT 1,
            `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        'entries' => "CREATE TABLE IF NOT EXISTS `entries` (
            `id`         VARCHAR(40)  NOT NULL PRIMARY KEY,
            `pt`         VARCHAR(100) NOT NULL,
            `week_num`   INT          NOT NULL DEFAULT 0,
            `user_id`    VARCHAR(40)  NOT NULL,
            `data`       MEDIUMTEXT,
            `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `updated_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            `deleted`    TINYINT(1)   NOT NULL DEFAULT 0,
            INDEX idx_pt (`pt`),
            INDEX idx_week (`week_num`),
            INDEX idx_user (`user_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        'plan_edits' => "CREATE TABLE IF NOT EXISTS `plan_edits` (
            `key_name`   VARCHAR(255) NOT NULL PRIMARY KEY,
            `value`      DOUBLE       NOT NULL DEFAULT 0,
            `updated_by` VARCHAR(40),
            `updated_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        'login_attempts' => "CREATE TABLE IF NOT EXISTS `login_attempts` (
            `id`         INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `login`      VARCHAR(60)  NOT NULL,
            `ip`         VARCHAR(45)  NOT NULL,
            `attempted_at` DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_login (`login`),
            INDEX idx_ip    (`ip`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    ];

    foreach ($tables as $name => $sql) {
        try {
            $pdo->exec($sql);
            step(true, "Таблица `$name`: OK");
        } catch (Exception $e) {
            step(false, "Таблица `$name`: " . $e->getMessage());
        }
    }

    if (!$errors) {
        $adminPass  = $_POST['admin_pass']  ?? '';
        $adminLogin = strtolower(trim($_POST['admin_login'] ?? 'admin'));
        $adminName  = htmlspecialchars(trim($_POST['admin_name'] ?? 'Администратор'), ENT_QUOTES);

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $adminPass) {
            if (strlen($adminPass) < 6) {
                step(false, 'Пароль должен быть минимум 6 символов');
            } else {
                try {
                    $check = $pdo->prepare('SELECT id FROM users WHERE login=?');
                    $check->execute([$adminLogin]);
                    $hash = password_hash($adminPass, PASSWORD_BCRYPT, ['cost' => 12]);
                    if ($check->fetch()) {
                        $pdo->prepare('UPDATE users SET password_hash=?,name=? WHERE login=?')
                            ->execute([$hash, $adminName, $adminLogin]);
                        step(true, "Пароль администратора `$adminLogin` обновлён");
                    } else {
                        $newId = 'u_' . bin2hex(random_bytes(8));
                        $pdo->prepare("INSERT INTO users(id,name,login,password_hash,role,color,ini,pt,access_pts,active) VALUES(?,?,?,?,'Администратор','#a78bfa','АДМ','',?,1)")
                            ->execute([$newId, $adminName, $adminLogin, $hash, json_encode([])]);
                        step(true, "Администратор `$adminLogin` создан");
                    }
                } catch (Exception $e) {
                    step(false, 'Создание admin: ' . $e->getMessage());
                }
            }
        }
    }
}

echo '<div class="card"><h3 style="margin:0 0 16px">Результат</h3>';
foreach ($steps as $s) {
    echo '<div class="step"><div class="dot '.($s['ok']?'ok':'err').'">'.($s['ok']?'✓':'✗').'</div>'.htmlspecialchars($s['msg']).'</div>';
}
echo '</div>';

$token_param = '?token=' . urlencode($token);

if (!$errors && !empty($pdo)):
?>
<div class="card">
  <h3 style="margin:0 0 12px">Установка завершена ✓</h3>
  <?php if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['admin_pass'])): ?>
  <p style="color:rgba(200,210,235,.7);font-size:14px;margin:0 0 16px">Задайте данные для администратора:</p>
  <form method="POST" action="install.php<?= htmlspecialchars($token_param) ?>">
    <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
    <label>Имя администратора</label>
    <input name="admin_name" value="Администратор" required>
    <label>Логин администратора</label>
    <input name="admin_login" value="admin" required pattern="[a-z0-9_]{3,}" title="Только строчные буквы, цифры, _">
    <label>Пароль (минимум 6 символов)</label>
    <input type="password" name="admin_pass" minlength="6" required>
    <button class="btn" type="submit">Создать администратора →</button>
  </form>
  <?php else: ?>
  <p class="ok">✓ Готово! После успешной установки:</p>
  <ul style="font-size:13px;color:rgba(200,210,235,.7);margin:8px 0 16px;padding-left:20px;line-height:2">
    <li>Закомментируйте или удалите install.php с сервера</li>
    <li>Или заблокируйте через .htaccess</li>
  </ul>
  <a class="btn" href="index.php">Открыть CRM →</a>
  <?php endif; ?>
</div>
<?php elseif ($errors): ?>
<div class="card">
  <p class="err">Ошибки:</p>
  <?php foreach ($errors as $e): ?><pre><?= htmlspecialchars($e) ?></pre><?php endforeach; ?>
  <p style="font-size:13px;color:rgba(200,210,235,.6)">Проверьте файл <code>.env</code> — DB_HOST, DB_NAME, DB_USER, DB_PASS.</p>
</div>
<?php endif; ?>
</body>
</html>
