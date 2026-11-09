<?php
declare(strict_types=1);

const SUBMONITOR_DB = '/opt/SubMonitor/data/submonitor.db';

function db(): SQLite3 {
    static $db = null;
    if ($db instanceof SQLite3) {
        return $db;
    }

    $dir = dirname(SUBMONITOR_DB);
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }

    $db = new SQLite3(SUBMONITOR_DB, SQLITE3_OPEN_READWRITE | SQLITE3_OPEN_CREATE);
    $db->busyTimeout(5000);
    // WAL is enabled once during database initialization; avoid changing journal mode on every request.
    $db->exec('PRAGMA synchronous=NORMAL;');
    $db->exec('PRAGMA temp_store=MEMORY;');
    $db->exec('PRAGMA cache_size=-32000;');
    $db->exec('PRAGMA mmap_size=67108864;');
    $db->exec('PRAGMA foreign_keys=ON;');
    return $db;
}

function initDatabase(): void {
    static $initialized = false;
    if ($initialized) return;

    $db = db();
    // Safe for an existing database and substantially reduces read/write contention.
    $db->exec('PRAGMA journal_mode=WAL;');
    $db->exec(<<<SQL
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_key TEXT NOT NULL UNIQUE,
    ts INTEGER NOT NULL,
    day TEXT NOT NULL,
    ip TEXT NOT NULL,
    token TEXT NOT NULL DEFAULT '-',
    status INTEGER NOT NULL,
    ua TEXT NOT NULL DEFAULT '',
    request_uri TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC);
CREATE INDEX IF NOT EXISTS idx_logs_ts_id ON logs(ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_logs_day ON logs(day);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
CREATE INDEX IF NOT EXISTS idx_logs_token ON logs(token);
CREATE INDEX IF NOT EXISTS idx_logs_status_ts ON logs(status, ts);
CREATE INDEX IF NOT EXISTS idx_logs_day_ip ON logs(day, ip);
CREATE INDEX IF NOT EXISTS idx_logs_day_token ON logs(day, token);

CREATE TABLE IF NOT EXISTS ip_info (
    ip TEXT PRIMARY KEY,
    info TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS importer_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    inode INTEGER NOT NULL DEFAULT 0,
    file_size INTEGER NOT NULL DEFAULT 0,
    offset INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO importer_state(id) VALUES (1);

CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS v2board_user_cache (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL DEFAULT 0,
    email TEXT NOT NULL DEFAULT '',
    plan_name TEXT NOT NULL DEFAULT '',
    banned INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_v2board_user_cache_uid ON v2board_user_cache(user_id);
CREATE TABLE IF NOT EXISTS v2board_ban_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_v2board_ban_history_uid_time ON v2board_ban_history(user_id, created_at DESC);
SQL);
    $initialized = true;
}

function dbScalar(string $sql, array $params = []): mixed {
    $stmt = db()->prepare($sql);
    foreach ($params as $k => $v) {
        $stmt->bindValue(is_int($k) ? $k + 1 : $k, $v, is_int($v) ? SQLITE3_INTEGER : SQLITE3_TEXT);
    }
    $result = $stmt->execute();
    $row = $result ? $result->fetchArray(SQLITE3_NUM) : false;
    return $row === false ? null : $row[0];
}
