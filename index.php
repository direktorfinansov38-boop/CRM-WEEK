<?php
// ═══════════════════════════════════════════════
//  Kimchi CRM — главная страница
//  Загружает список пользователей из БД (без
//  паролей и логинов) и показывает на странице входа
// ═══════════════════════════════════════════════

require_once __DIR__ . '/config.php';

$users = [];
try {
    $pdo = new PDO(
        'mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4',
        DB_USER, DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    // Логин не передаём на страницу — пользователь вводит сам
    $rows = $pdo->query(
        'SELECT id, name, role, color, ini, pt, access_pts FROM users WHERE active=1 ORDER BY role DESC, name'
    )->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as &$r) {
        $r['accessPts'] = json_decode($r['access_pts'] ?? '[]', true);
        unset($r['access_pts']);
    }
    $users = $rows;
} catch (Exception $e) {
    // БД недоступна — покажем страницу с пустым списком пользователей
    // Пользователь сможет ввести логин вручную
}

// Безопасное кодирование для вставки в JS
$usersJson = json_encode($users, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

$html = file_get_contents(__DIR__ . '/index.html');
if ($html === false) {
    http_response_code(500);
    echo 'Ошибка: файл index.html не найден';
    exit;
}

// Вставляем пользователей — надёжнее чем str_replace через маркер
$inject = '<script>
(function(){
  var su = ' . $usersJson . ';
  if (!su || !su.length) return;
  var tries = 0;
  var t = setInterval(function(){
    tries++;
    if (tries > 50) { clearInterval(t); return; } // max 5 sec
    if (typeof USERS !== "undefined" && typeof normUser === "function" && typeof initLogin === "function") {
      clearInterval(t);
      var added = false;
      su.forEach(function(u){
        var role = u.role || "Управляющий";
        var pts  = Array.isArray(u.accessPts) ? u.accessPts : [];
        if (role === "Администратор") pts = (typeof ALL_PTS !== "undefined") ? ALL_PTS.slice() : [];
        var nu = {
          id: u.id, name: u.name, role: role,
          color: u.color || "#a78bfa",
          ini: (u.ini || u.name.slice(0,2)).slice(0,5),
          pt: u.pt || (pts[0] || ""),
          accessPts: pts,
          login: "", password: ""  // пустые — пользователь вводит сам
        };
        var found = false;
        for (var i = 0; i < USERS.length; i++) {
          if (USERS[i].id === nu.id) { USERS[i] = normUser(nu); found = true; break; }
        }
        if (!found) { USERS.push(normUser(nu)); added = true; }
      });
      if (added || su.length) initLogin();
    }
  }, 100);
})();
</script>';

// Вставляем перед </body>
if (str_contains($html, '</body>')) {
    $html = str_replace('</body>', $inject . '</body>', $html);
} else {
    $html .= $inject;
}

// Отправляем заголовки
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');

echo $html;
