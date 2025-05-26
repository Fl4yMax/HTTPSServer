<?php
// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set HTTP headers
header("Content-Type: text/html; charset=UTF-8");
header("X-Powered-By: MyCppServer");

// Simple HTML output
echo "<html>";
echo "<head><title>PHP Response</title></head>";
echo "<body>";
echo "<h1>Hello from PHP!</h1>";
echo "<p>This is a test response from the PHP script.</p>";

// Print server variables for debugging
echo "<h2>Server Info</h2>";
echo "<pre>";
print_r($_SERVER);
echo "</pre>";

echo "</body></html>";

phpinfo();
?>
