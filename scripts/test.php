<?php
header("Content-Type: text/html; charset=UTF-8");

// Simulating dynamic content
echo "<h1>PHP Execution Test</h1>";
echo "<p>Current time: " . date("Y-m-d H:i:s") . "</p>";

// Read GET parameters
if (isset($_GET['name'])) {
    echo "<p>Hello, " . htmlspecialchars($_GET['name']) . "!</p>";
}

// Read POST data
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $data = file_get_contents("php://input");
    echo "<h2>Received POST Data:</h2>";
    echo "<pre>" . htmlspecialchars($data) . "</pre>";
}
?>