<?php
declare(strict_types=1);
namespace Oleg\Emergency;
use PDO;
use RuntimeException;
use Throwable;

const SITES = ['potrebpravo.ru', 'semya-yurist.ru'];
const MAX_PER_IP_20_MIN = 5;
const POLICY_VERSION = '2026-11-17';

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function page(string $title, string $body): string {
    return '<!doctype html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>'.e($title).'</title><style>body{max-width:650px;margin:36px auto;padding:0 18px;font:16px/1.5 system-ui,Arial,sans-serif;color:#172a41}label{display:block;margin:16px 0 6px;font-weight:600}input,textarea{box-sizing:border-box;width:100%;padding:12px;font:inherit;border:1px solid #77889d;border-radius:6px}textarea{min-height:130px}input[type=checkbox]{width:auto;min-width:18px;min-height:18px;margin-right:9px}button{padding:14px 20px;border:0;background:#145bb7;color:white;border-radius:7px;font:inherit;cursor:pointer}a{color:#145bb7}a:focus-visible,button:focus-visible{outline:3px solid #dc8714} .muted{color:#43536b}.honeypot{position:absolute;left:-10000px}</style></head><body><main>'.$body.'</main></body></html>';
}
function host(): string {
    $h=strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    if (!in_array($h, SITES, true)) throw new RuntimeException('Unsupported host');
    $test=getenv('OLEG_INTAKE_TEST_MODE') === '1' && in_array((string)($_SERVER['REMOTE_ADDR']??''),['127.0.0.1','::1'],true);
    if (!$test && ($_SERVER['HTTPS']??'') !== 'on' && (string)($_SERVER['SERVER_PORT']??'') !== '443') throw new RuntimeException('HTTPS required');
    return $h;
}
function private_home(): string {
    $root = dirname(dirname($_SERVER['SCRIPT_FILENAME']));
    return dirname($root).'/.oleg-emergency-intake-v17';
}
function key(string $home): string {
    $p=$home.'/secretbox.key';
    if (is_link($p)||!is_file($p)) throw new RuntimeException('Missing secret');
    $k=file_get_contents($p);
    if ($k===false||strlen($k)!==SODIUM_CRYPTO_SECRETBOX_KEYBYTES) throw new RuntimeException('Invalid secret');
    return $k;
}
function db(string $home): PDO {
    $p=$home.'/intake.sqlite';
    if (is_link($home)||!is_dir($home)||is_link($p)||!is_file($p)) throw new RuntimeException('Intake is not installed');
    $db=new PDO('sqlite:'.$p,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>4]);
    $db->exec('PRAGMA busy_timeout=4000');
    $db->exec('PRAGMA synchronous=FULL');
    return $db;
}
function install(string $home): void {
    umask(0077);
    if (!is_dir($home) && !mkdir($home,0700,true)) throw new RuntimeException('Cannot create private inbox');
    if (is_link($home)) throw new RuntimeException('Unsafe inbox symlink');
    chmod($home,0700);
    $path=$home.'/secretbox.key';
    if (!is_file($path)) {
        $fd=@fopen($path,'x');
        if (!$fd) throw new RuntimeException('Cannot create secret');
        try {
            $bytes=random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
            if (fwrite($fd,$bytes)!==strlen($bytes)) throw new RuntimeException('Cannot write secret');
            fflush($fd);
        } finally { fclose($fd); }
    }
    chmod($path,0600);
    key($home);
    $p=$home.'/intake.sqlite';
    $db=new PDO('sqlite:'.$p,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA synchronous=FULL');
    $db->exec('PRAGMA secure_delete=ON');
    $db->exec('CREATE TABLE IF NOT EXISTS requests (
        site TEXT NOT NULL, request_id TEXT NOT NULL, receipt TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL, payload_hash TEXT NOT NULL,
        nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, ip_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT \'awaiting_manual_review\',
        PRIMARY KEY(site,request_id)
    )');
    $db->exec('CREATE INDEX IF NOT EXISTS requests_ip_time ON requests(ip_hash,created_at)');
    chmod($p,0600);
}
function save(PDO $db,string $secret,string $site,string $clientIP,array $f): array {
    $id=(string)($f['request_id']??'');
    $name=trim((string)($f['name']??''));
    $tel=trim((string)($f['phone']??''));
    $problem=trim((string)($f['problem']??''));
    if (!preg_match('/^[0-9a-f]{32}$/D',$id)) throw new \InvalidArgumentException('Пожалуйста, откройте форму заново.');
    if (mb_strlen($name)<2||mb_strlen($name)>120||preg_match('/[<>\x00-\x1f]/u',$name)) throw new \InvalidArgumentException('Укажите имя (2–120 символов).');
    if (!preg_match('/^\+?[0-9 ()-]{10,22}$/D',$tel)||strlen(preg_replace('/\D/','',$tel))<10) throw new \InvalidArgumentException('Укажите корректный телефон.');
    if (mb_strlen($problem)<10||mb_strlen($problem)>3000||str_contains($problem,"\0")) throw new \InvalidArgumentException('Опишите проблему (10–3000 символов).');
    if (($f['consent']??'')!=='yes') throw new \InvalidArgumentException('Необходимо согласие на обработку данных.');
    if (trim((string)($f['website']??''))!=='') throw new \InvalidArgumentException('Обращение не принято.');
    $plain=json_encode(['name'=>$name,'phone'=>$tel,'problem'=>$problem,'consent'=>true,'policy_version'=>POLICY_VERSION],JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
    $hash=hash_hmac('sha256',$site."\0".$plain,$secret);
    $ipHash=hash_hmac('sha256',$clientIP,$secret);
    $db->exec('BEGIN IMMEDIATE');
    try {
        $query=$db->prepare('SELECT receipt,payload_hash FROM requests WHERE site=? AND request_id=?');
        $query->execute([$site,$id]);
        $old=$query->fetch(PDO::FETCH_ASSOC);
        if ($old!==false) {
            if (!hash_equals($old['payload_hash'],$hash)) throw new \DomainException('Этот номер формы уже использован с другими данными.');
            $db->exec('COMMIT');
            return ['receipt'=>$old['receipt'],'duplicate'=>true];
        }
        $rate=$db->prepare('SELECT COUNT(*) FROM requests WHERE ip_hash=? AND created_at>=?');
        $rate->execute([$ipHash,time()-1200]);
        if ((int)$rate->fetchColumn()>=MAX_PER_IP_20_MIN) throw new \OverflowException('Слишком много обращений за короткое время.');
        $nonce=random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encrypted=sodium_crypto_secretbox($plain,$nonce,$secret);
        $receipt=bin2hex(random_bytes(16));
        $insert=$db->prepare('INSERT INTO requests (site,request_id,receipt,created_at,payload_hash,nonce,ciphertext,ip_hash) VALUES (?,?,?,?,?,?,?,?)');
        $insert->bindValue(1,$site);
        $insert->bindValue(2,$id);
        $insert->bindValue(3,$receipt);
        $insert->bindValue(4,time(),PDO::PARAM_INT);
        $insert->bindValue(5,$hash);
        $insert->bindValue(6,$nonce,PDO::PARAM_LOB);
        $insert->bindValue(7,$encrypted,PDO::PARAM_LOB);
        $insert->bindValue(8,$ipHash);
        $insert->execute();
        $db->exec('COMMIT');
        return ['receipt'=>$receipt,'duplicate'=>false];
    } catch (Throwable $exc) {
        try { $db->exec('ROLLBACK'); } catch (Throwable $ignored) { /* Preserve original failure. */ }
        throw $exc;
    }
}
function form_html(string $host,string $csrf,string $id,string $error='',array $values=[]): string {
    $v=static fn(string $field):string=>e((string)($values[$field]??''));
    $body='<h1>Резервное обращение к юристу</h1><p class="muted">Эта форма сохраняет обращение на нашем сервере независимо от Битрикс24. Передача в CRM пока не подтверждается автоматически. В срочных случаях позвоните по телефону, указанному на сайте.</p>';
    if ($error!=='') $body.='<p role="alert" style="color:#9d1b27"><strong>'.e($error).'</strong></p>';
    $body.='<form method="post" action="/emergency-lead.php" accept-charset="UTF-8">';
    $body.='<input type="hidden" name="csrf" value="'.e($csrf).'"><input type="hidden" name="request_id" value="'.e($id).'">';
    $body.='<label for="name">Ваше имя *</label><input id="name" name="name" maxlength="120" autocomplete="name" required value="'.$v('name').'">';
    $body.='<label for="phone">Телефон *</label><input id="phone" name="phone" maxlength="22" type="tel" autocomplete="tel" required value="'.$v('phone').'">';
    $body.='<label for="problem">Краткое описание проблемы *</label><textarea id="problem" name="problem" maxlength="3000" minlength="10" required>'.$v('problem').'</textarea>';
    $body.='<label for="website" class="honeypot">Оставьте пустым</label><input class="honeypot" id="website" name="website" tabindex="-1" autocomplete="off">';
    $body.='<p><label><input type="checkbox" value="yes" name="consent" required> Даю согласие на обработку данных для ответа на обращение согласно <a href="/consent.html" target="_blank" rel="noopener noreferrer">согласию</a> и <a href="/privacy.html" target="_blank" rel="noopener noreferrer">политике</a>.</label></p>';
    $body.='<button type="submit">Сохранить обращение</button></form><p><a href="https://'.e($host).'/">Вернуться на сайт</a></p>';
    return page('Резервная заявка', $body);
}
