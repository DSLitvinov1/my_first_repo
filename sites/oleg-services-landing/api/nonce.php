<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') api_json(405, ['status'=>'method_not_allowed']);
api_session();
$_SESSION['lead_nonce'] = bin2hex(random_bytes(24));
$_SESSION['lead_nonce_at'] = time();
api_json(200, ['token'=>$_SESSION['lead_nonce']]);
