<?php
declare(strict_types=1);
require_once __DIR__.'/intake-core.php';
use function Oleg\Emergency\{install,db,key};
if (PHP_SAPI!=='cli') { http_response_code(404);exit; }
$operation=$argv[1]??'';
$home=$argv[2]??'';
if (!in_array($operation,['install','status','list','read'],true) || !str_starts_with($home,'/') || str_contains($home,'/public_html')) {
    fwrite(STDERR,"Usage: php console.php install|status|list|read /absolute/private/path [receipt --confirm-sensitive]\n");exit(2);
}
try {
    if ($operation==='install') {
        install($home);
        echo "INITIALIZED_PRIVATE_DURABLE_INBOX\n";
        exit;
    }
    $secret=key($home);
    $pdo=db($home);
    if ($operation==='status') {
        $sql="SELECT site,status,COUNT(*) AS count FROM requests GROUP BY site,status ORDER BY site,status";
        $rows=$pdo->query($sql)->fetchAll(\PDO::FETCH_ASSOC);
        echo json_encode(['stored_counts'=>$rows],JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT)."\n";
    } elseif ($operation==='list') {
        $rows=$pdo->query("SELECT site,receipt,created_at,status FROM requests ORDER BY created_at DESC LIMIT 100")->fetchAll(\PDO::FETCH_ASSOC);
        echo json_encode(['receipts_only_no_pii'=>$rows],JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT)."\n";
    } else {
        $receipt=$argv[3]??'';
        if (!preg_match('/^[0-9a-f]{32}$/D',$receipt) || ($argv[4]??'')!=='--confirm-sensitive') {
            fwrite(STDERR,"Sensitive receipt read requires a valid receipt and --confirm-sensitive; do not run in shared logs.\n");exit(2);
        }
        $s=$pdo->prepare('SELECT site,receipt,created_at,nonce,ciphertext FROM requests WHERE receipt=?');
        $s->execute([$receipt]);
        $row=$s->fetch(\PDO::FETCH_ASSOC);
        if (!$row) { fwrite(STDERR,"Not found\n");exit(4); }
        $json=sodium_crypto_secretbox_open($row['ciphertext'],$row['nonce'],$secret);
        if ($json===false) throw new \RuntimeException('Decrypt refused');
        echo json_encode(['site'=>$row['site'],'receipt'=>$receipt,'created_at'=>$row['created_at'],'contact'=>json_decode($json,true,512,JSON_THROW_ON_ERROR)],JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT)."\n";
    }
} catch (\Throwable $e) {
    fwrite(STDERR,"INTAKE_UNAVAILABLE (details withheld)\n");exit(3);
}
