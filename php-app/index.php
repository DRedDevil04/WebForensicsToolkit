<?php
// Simple PHP demo service
$time = date("Y-m-d H:i:s");
$ip = $_SERVER['REMOTE_ADDR'];
$message = "[$time] Request from $ip - " . $_SERVER['REQUEST_METHOD'] . " " . $_SERVER['REQUEST_URI'] . "\n";

file_put_contents(__DIR__ . "/logs/app.log", $message, FILE_APPEND);

echo "Hello from PHP Web Service!<br>";
echo "Logged your request at $time";
?>
