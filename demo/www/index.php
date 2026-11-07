<?php
echo "<h1>nginx htaccess module + PHP-FPM 8.4</h1>";
echo "<h2>Server Info</h2>";
echo "<p>PHP Version: " . phpversion() . "</p>";
echo "<p>Server Software: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'N/A') . "</p>";
echo "<p>Request URI: " . htmlspecialchars($_SERVER['REQUEST_URI'] ?? '', ENT_QUOTES, 'UTF-8') . "</p>";
echo "<p>Script Name: " . htmlspecialchars($_SERVER['SCRIPT_NAME'] ?? '', ENT_QUOTES, 'UTF-8') . "</p>";
echo "<p>Query String: " . htmlspecialchars($_SERVER['QUERY_STRING'] ?? '', ENT_QUOTES, 'UTF-8') . "</p>";

echo "<h2>.htaccess Tests</h2>";
echo "<ul>";
echo "<li><a href='/about'>Pretty URL /about</a> (should rewrite to index.php)</li>";
echo "<li><a href='/page/42'>Pretty URL /page/42</a> (should rewrite with param)</li>";
echo "<li><a href='/test.css'>Static CSS</a> (should get AddType)</li>";
echo "</ul>";

echo "<h2>Received Parameters</h2>";
echo "<pre>";
echo htmlspecialchars(print_r($_GET, true), ENT_QUOTES, 'UTF-8');
echo "</pre>";

echo "<h2>Request Headers (from PHP)</h2>";
echo "<pre>";
foreach (getallheaders() as $name => $value) {
    echo htmlspecialchars("$name: $value") . "\n";
}
echo "</pre>";
