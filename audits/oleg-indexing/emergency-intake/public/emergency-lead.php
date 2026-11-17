<?php
declare(strict_types=1);
use function Oleg\Emergency\{e,page,form_html,host,private_home,db,key,save,tracking};
use const Oleg\Emergency\{SITES,MAX_PER_IP_20_MIN};

umask(0077);
$private=dirname(dirname(__DIR__)).'/.oleg-emergency-intake-v17';
if (!is_file($private.'/intake-core.php')) {
    http_response_code(503);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'Резервная форма временно недоступна. Обратитесь по телефону с основного сайта.';
    exit;
}
require_once $private.'/intake-core.php';
header('Cache-Control: no-store, max-age=0');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');
header('Content-Type: text/html; charset=UTF-8');
$test=getenv('OLEG_INTAKE_TEST_MODE') === '1' && in_array((string)($_SERVER['REMOTE_ADDR']??''),['127.0.0.1','::1'],true);
session_name('oleg_emergency_intake');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>!$test,'httponly'=>true,'samesite'=>'Strict']);
ini_set('session.use_strict_mode','1');
if (!session_start()) {
    http_response_code(503);
    echo page('Ошибка связи','<h1>Обращение не сохранено</h1><p>Повторите позже или позвоните юристу.</p>');
    exit;
}
try {
    $site=host();
    $pdo=db($private);
    $secret=key($private);
} catch (\Throwable $e) {
    http_response_code(503);
    echo page('Временно недоступно','<h1>Резервная форма временно недоступна</h1><p>Обращение не сохранено. Воспользуйтесь телефоном на сайте.</p>');
    exit;
}
$method=(string)($_SERVER['REQUEST_METHOD']??'GET');
$_SESSION['csrf']??=bin2hex(random_bytes(32));
if ($method==='GET') {
    $receipt=(string)($_GET['receipt']??'');
    if ($receipt!=='' && preg_match('/^[0-9a-f]{32}$/D',$receipt) && isset($_SESSION['receipts'][$receipt])) {
        echo page('Обращение сохранено','<h1>Обращение сохранено на сервере</h1><p>Номер подтверждения: <strong>'.e($receipt).'</strong>.</p><p>Это подтверждает сохранение у нас, <strong>но не поступление в Битрикс24</strong>. Если вопрос срочный, позвоните по номеру на основном сайте.</p><p><a href="https://'.e($site).'/">На сайт</a></p>');
        exit;
    }
    $id=bin2hex(random_bytes(16));
    $_SESSION['last_request_id']=$id;
    $_SESSION['last_source']=tracking($_GET,(string)($_SERVER['HTTP_REFERER']??''),$site);
    echo form_html($site,$_SESSION['csrf'],$id);
    exit;
}
if ($method!=='POST') {
    http_response_code(405);
    header('Allow: GET, POST');
    echo page('Неподдерживаемый запрос','<h1>Действие недоступно</h1>');
    exit;
}
$length=(int)($_SERVER['CONTENT_LENGTH']??0);
if ($length<=0||$length>8192) {
    http_response_code(413);
    echo page('Слишком много данных','<h1>Обращение не сохранено</h1><p>Проверьте объём текста и повторите попытку.</p>');
    exit;
}
if (!str_starts_with(strtolower((string)($_SERVER['CONTENT_TYPE']??'')),'application/x-www-form-urlencoded')) {
    http_response_code(415);
    echo page('Неподдерживаемый формат','<h1>Обращение не сохранено</h1>');
    exit;
}
$expectedOrigin=($test?'http':'https').'://'.$site;
$origin=(string)($_SERVER['HTTP_ORIGIN']??'');
$referer=(string)($_SERVER['HTTP_REFERER']??'');
if (($origin!=='' && $origin!==$expectedOrigin) || ($origin==='' && $referer!=='' && !str_starts_with($referer,$expectedOrigin.'/'))) {
    http_response_code(403);
    echo page('Защита данных','<h1>Обращение не сохранено</h1><p>Откройте форму с основного сайта.</p>');
    exit;
}
if (!hash_equals((string)$_SESSION['csrf'],(string)($_POST['csrf']??''))) {
    http_response_code(403);
    echo page('Защита данных','<h1>Обращение не сохранено</h1><p>Обновите страницу и повторите попытку.</p>');
    exit;
}
if ((string)($_POST['request_id']??'')!==(string)($_SESSION['last_request_id']??'')) {
    http_response_code(403);
    echo page('Защита данных','<h1>Обращение не сохранено</h1><p>Обновите форму и повторите попытку.</p>');
    exit;
}
try {
    $saved=save($pdo,$secret,$site,(string)($_SERVER['REMOTE_ADDR']??''),$_POST,(array)($_SESSION['last_source']??[]));
    $_SESSION['receipts'][$saved['receipt']]=time();
    if (count($_SESSION['receipts'])>12) $_SESSION['receipts']=array_slice($_SESSION['receipts'],-12,null,true);
    session_write_close();
    header('Location: /emergency-lead.php?receipt='.$saved['receipt'],true,303);
    exit;
} catch (\InvalidArgumentException $e) {
    http_response_code(422);
    echo form_html($site,$_SESSION['csrf'],(string)($_SESSION['last_request_id']??''),$e->getMessage(),$_POST);
} catch (\DomainException $e) {
    http_response_code(409);
    echo page('Конфликт данных','<h1>Обращение не сохранено</h1><p>Откройте форму заново и повторите попытку.</p>');
} catch (\OverflowException $e) {
    http_response_code(429);
    header('Retry-After: 1200');
    echo page('Слишком много обращений','<h1>Обращение не сохранено</h1><p>Повторите попытку позже или воспользуйтесь телефоном на сайте.</p>');
} catch (\Throwable $e) {
    http_response_code(503);
    echo page('Ошибка сохранения','<h1>Не удалось сохранить обращение</h1><p>Пожалуйста, повторите попытку позже. В срочных случаях позвоните юристу.</p>');
}
