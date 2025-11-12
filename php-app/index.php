<?php
// index.php
// Forensic Web App Logger — tracks requests, uploads, and metadata for ELK analysis.

date_default_timezone_set('UTC');

$baseDir = __DIR__;
$logDir = $baseDir . '/logs';
$uploadsDir = $baseDir . '/uploads';

if (!is_dir($logDir)) mkdir($logDir, 0755, true);
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0755, true);

$accessLog = "$logDir/access.log";
$uploadLog = "$logDir/upload.log";

// ---------------------------
// Helper: Write log function
// ---------------------------
function write_log($file, $data) {
    $json = json_encode($data, JSON_UNESCAPED_SLASHES);
    file_put_contents($file, $json . PHP_EOL, FILE_APPEND | LOCK_EX);
}

// ---------------------------
// Common request metadata
// ---------------------------
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$method = $_SERVER['REQUEST_METHOD'] ?? 'CLI';
$uri = $_SERVER['REQUEST_URI'] ?? '';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$timestamp = gmdate('Y-m-d\TH:i:s\Z');
$session_id = bin2hex(random_bytes(8));

// ---------------------------
// Log every request
// ---------------------------
$accessEntry = [
    'timestamp' => $timestamp,
    'session_id' => $session_id,
    'client_ip' => $client_ip,
    'method' => $method,
    'uri' => $uri,
    'user_agent' => $user_agent,
    'query' => $_GET,
    'post' => $_POST,
    'cookies' => $_COOKIE,
    'referer' => $_SERVER['HTTP_REFERER'] ?? '',
    'status' => 200
];
write_log($accessLog, $accessEntry);

// ---------------------------
// Handle file uploads
// ---------------------------
if ($method === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $uploadStatus = 'failed';
    $fileName = basename($file['name']);
    $target = $uploadsDir . '/' . $fileName;

    if ($file['error'] === UPLOAD_ERR_OK && move_uploaded_file($file['tmp_name'], $target)) {
        $uploadStatus = 'success';
    }

    $uploadEntry = [
        'timestamp' => $timestamp,
        'session_id' => $session_id,
        'client_ip' => $client_ip,
        'file_name' => $fileName,
        'file_size' => $file['size'],
        'mime_type' => $file['type'],
        'upload_status' => $uploadStatus,
        'target_path' => realpath($target)
    ];
    write_log($uploadLog, $uploadEntry);
}

// ---------------------------
// Basic HTML Frontend
// ---------------------------
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic Upload Portal</title>
  <style>
    body { font-family: sans-serif; margin: 50px; background: #f5f5f5; color: #333; }
    h1 { color: #444; }
    form { background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 400px; }
    input[type="file"], input[type="submit"] { margin-top: 10px; }
    .log { margin-top: 20px; font-size: 0.9em; color: #666; }
  </style>
</head>
<body>
  <h1>🕵️ Web Forensics Upload Portal</h1>
  <p>Simulate normal and malicious file uploads for forensic logging.</p>

  <form action="index.php" method="POST" enctype="multipart/form-data">
    <label>Select file to upload:</label><br>
    <input type="file" name="file" required><br>
    <input type="submit" value="Upload File">
  </form>

  <div class="log">
    <p>All requests logged to <code>logs/access.log</code> and uploads to <code>logs/upload.log</code>.</p>
  </div>
</body>
</html>
