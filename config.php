<?php
// ═══════════════════════════════════════════════
//  Kimchi CRM — конфигурация
//  Credentials загружаются из .env (не из кода!)
// ═══════════════════════════════════════════════

// Загружаем .env если нет переменных окружения
function loadEnv(string $path): void {
    if (!file_exists($path)) return;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (str_starts_with(trim($line), '#') || !str_contains($line, '=')) continue;
        [$key, $val] = explode('=', $line, 2);
        $key = trim($key); $val = trim($val);
        if (!getenv($key)) putenv("$key=$val");
    }
}

loadEnv(__DIR__ . '/.env');

define('DB_HOST',        getenv('DB_HOST')        ?: 'localhost');
define('DB_NAME',        getenv('DB_NAME')        ?: 'kimchi_crm');
define('DB_USER',        getenv('DB_USER')        ?: 'root');
define('DB_PASS',        getenv('DB_PASS')        ?: '');
define('INSTALL_TOKEN',  getenv('INSTALL_TOKEN')  ?: '');

// Настройки сессии
define('SESSION_LIFETIME', 86400); // 24 часа
