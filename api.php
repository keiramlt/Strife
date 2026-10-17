<?php
// api.php - Hardened relay for the E2EE chat.
// The server only stores opaque ciphertext + metadata. It never sees plaintext
// and never holds the key. Security still rests entirely on the room password.

declare(strict_types=1);

// --- Security headers ---
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

// --- (Recommended) require HTTPS in production. Comment out for local dev. ---
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
      || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
      || in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true);
if (!$https) {
    http_response_code(400);
    echo json_encode(['error' => 'HTTPS required']);
    exit;
}

// --- Config ---
const MAX_BODY_BYTES   = 65536;   // reject anything larger than 64 KB
const MAX_USER_LEN     = 32;
const MAX_CT_BYTES     = 8192;    // max ciphertext length per message
const IV_LEN           = 12;
const MAX_MESSAGES     = 50;
const RATE_MAX         = 15;      // max posts ...
const RATE_WINDOW_MS   = 10000;   // ...per 10 seconds, per IP

// --- Paths (rooms/ should ideally live OUTSIDE the webroot; see .htaccess) ---
$dir = __DIR__ . '/rooms';
if (!is_dir($dir)) {
    mkdir($dir, 0700, true);
}

function fail(int $code, string $msg): never {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

// --- Resolve room name safely (regex blocks path traversal) ---
$room = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($_GET['room'] ?? ''));
if ($room === '' || strlen($room) > 64) {
    fail(400, 'Invalid room');
}
$file     = $dir . '/room_' . $room . '.json';
$saltFile = $dir . '/room_' . $room . '.salt';

$action = $_GET['action'] ?? '';

/**
 * Read a JSON array from a file under an exclusive lock, returning [handle, data].
 * Caller must fclose($fh) to release the lock.
 */
function open_locked(string $path) {
    $fh = fopen($path, 'c+');
    if ($fh === false) { fail(500, 'Storage error'); }
    if (!flock($fh, LOCK_EX)) { fclose($fh); fail(500, 'Lock error'); }
    $raw  = stream_get_contents($fh);
    $data = $raw !== '' ? json_decode($raw, true) : [];
    if (!is_array($data)) { $data = []; }
    return [$fh, $data];
}

function write_locked($fh, array $data): void {
    $json = json_encode(array_values($data));
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, $json);
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
}

// --- action=salt : return (and lazily create) a RANDOM per-room salt ---
// The salt is public by design; it only needs to be unique + unpredictable so
// that attackers can't precompute password tables against a known room name.
if ($action === 'salt') {
    $fh = fopen($saltFile, 'c+');
    if ($fh === false) { fail(500, 'Storage error'); }
    flock($fh, LOCK_EX);
    $existing = trim(stream_get_contents($fh));
    if ($existing === '') {
        $salt = base64_encode(random_bytes(16));
        ftruncate($fh, 0); rewind($fh); fwrite($fh, $salt); fflush($fh);
    } else {
        $salt = $existing;
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    echo json_encode(['salt' => $salt]);
    exit;
}

// --- POST: store one message ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Reject oversized bodies before reading them fully.
    $len = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($len > MAX_BODY_BYTES) { fail(413, 'Payload too large'); }

    $raw = file_get_contents('php://input', false, null, 0, MAX_BODY_BYTES + 1);
    if ($raw === false || strlen($raw) > MAX_BODY_BYTES) { fail(413, 'Payload too large'); }

    $input = json_decode($raw, true);
    if (!is_array($input)) { fail(400, 'Invalid JSON'); }

    // --- Strict structure validation: only whitelisted, well-formed fields ---
    $user = $input['user'] ?? null;
    $iv   = $input['iv'] ?? null;
    $ct   = $input['ciphertext'] ?? null;
    $ts   = $input['ts'] ?? null; // client-authenticated timestamp (bound in AAD)

    if (!is_string($user) || $user === '' || strlen($user) > MAX_USER_LEN) {
        fail(400, 'Invalid user');
    }
    if (!is_array($iv) || count($iv) !== IV_LEN) {
        fail(400, 'Invalid iv');
    }
    if (!is_array($ct) || count($ct) < 1 || count($ct) > MAX_CT_BYTES) {
        fail(400, 'Invalid ciphertext');
    }
    foreach ($iv as $b) { if (!is_int($b) || $b < 0 || $b > 255) fail(400, 'Invalid iv byte'); }
    foreach ($ct as $b) { if (!is_int($b) || $b < 0 || $b > 255) fail(400, 'Invalid ct byte'); }
    if (!is_int($ts)) { fail(400, 'Invalid ts'); }

    // --- Simple per-IP rate limit (flock-protected) ---
    $ip      = $_SERVER['REMOTE_ADDR'] ?? '0';
    $rlFile  = $dir . '/rl_' . preg_replace('/[^a-fA-F0-9:.]/', '', $ip) . '.json';
    $nowMs   = (int)(microtime(true) * 1000);
    [$rfh, $hits] = open_locked($rlFile);
    $hits = array_values(array_filter($hits, fn($t) => is_int($t) && $t > $nowMs - RATE_WINDOW_MS));
    if (count($hits) >= RATE_MAX) {
        flock($rfh, LOCK_UN); fclose($rfh);
        fail(429, 'Rate limit exceeded');
    }
    $hits[] = $nowMs;
    write_locked($rfh, $hits);

    // --- Append the message atomically ---
    $clean = [
        'user'       => $user,
        'iv'         => array_map('intval', $iv),
        'ciphertext' => array_map('intval', $ct),
        'ts'         => $ts,                 // authenticated (client) timestamp
        'timestamp'  => $nowMs,              // server receive time, used for polling
    ];

    [$fh, $messages] = open_locked($file);
    $messages[] = $clean;
    while (count($messages) > MAX_MESSAGES) { array_shift($messages); }
    write_locked($fh, $messages);

    echo json_encode(['status' => 'success']);
    exit;
}

// --- GET: fetch messages newer than last_time ---
$last_time = isset($_GET['last_time']) ? (float)$_GET['last_time'] : 0.0;
$messages  = file_exists($file) ? json_decode((string)file_get_contents($file), true) : [];
if (!is_array($messages)) { $messages = []; }

$new = array_values(array_filter($messages, function ($m) use ($last_time) {
    return isset($m['timestamp']) && $m['timestamp'] > $last_time;
}));

echo json_encode($new);
