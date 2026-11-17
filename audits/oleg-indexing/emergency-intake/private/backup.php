<?php
declare(strict_types=1);
/** Atomic-enough consistent SQLite snapshot with a separate private Sodium key copy. */
require_once __DIR__.'/intake-core.php';
use function Oleg\Emergency\{db,key};
if (PHP_SAPI!=='cli') { http_response_code(404);exit; }
$home=$argv[1]??'';
$mode=$argv[2]??'backup';
if (!in_array($mode,['backup','verify'],true) || !str_starts_with($home,'/') || str_contains($home,'/public_html')) {
    fwrite(STDERR,"BACKUP_INVALID_CONFIG\n");exit(2);
}
try {
    $secret=key($home);
    $pdo=db($home);
    $dir=$home.'/backups';
    if (!is_dir($dir) && !mkdir($dir,0700,true)) throw new RuntimeException('Backup directory unavailable');
    if (is_link($dir)) throw new RuntimeException('Backup directory symlink refused');
    chmod($dir,0700);
    if ($mode==='backup') {
        $suffix=gmdate('Ymd-His').'-'.bin2hex(random_bytes(5));
        $sqlite=$dir.'/'.$suffix.'.sqlite';
        $keyfile=$dir.'/'.$suffix.'.key';
        $manifest=$dir.'/'.$suffix.'.json';
        $pdo->exec('VACUUM INTO '.$pdo->quote($sqlite));
        if (file_put_contents($keyfile,$secret,LOCK_EX)!==strlen($secret)) throw new RuntimeException('Key backup write failed');
        chmod($sqlite,0600);
        chmod($keyfile,0600);
        $data=['snapshot'=>$suffix,'db_size'=>filesize($sqlite),'db_sha256'=>hash_file('sha256',$sqlite),'encrypted'=>true,'contains_personal_data'=>true];
        if (file_put_contents($manifest,json_encode($data,JSON_THROW_ON_ERROR)."\n",LOCK_EX)===false) throw new RuntimeException('Manifest write failed');
        chmod($manifest,0600);
        echo "PRIVATE_BACKUP_WRITTEN_AND_PROTECTED\n";
    }
    $files=glob($dir.'/*.json');
    if (!$files || !is_array($files)) throw new RuntimeException('No backup manifest');
    $manifest=end($files);
    $data=json_decode(file_get_contents($manifest),true,512,JSON_THROW_ON_ERROR);
    $prefix=substr($manifest,0,-5);
    if (!is_file($prefix.'.sqlite') || !is_file($prefix.'.key') || hash_file('sha256',$prefix.'.sqlite')!==($data['db_sha256']??'')) throw new RuntimeException('Snapshot checksum mismatch');
    $keycopy=file_get_contents($prefix.'.key');
    if (!is_string($keycopy)||!hash_equals($secret,$keycopy)) throw new RuntimeException('Backup encryption key mismatch');
    $restored=new PDO('sqlite:'.$prefix.'.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    if ($restored->query('PRAGMA integrity_check')->fetchColumn()!=='ok') throw new RuntimeException('SQLite integrity failed');
    $row=$restored->query('SELECT nonce,ciphertext FROM requests ORDER BY created_at DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
    if ($row!==false && sodium_crypto_secretbox_open($row['ciphertext'],$row['nonce'],$keycopy)===false) throw new RuntimeException('Encrypted record unreadable in snapshot');
    echo "BACKUP_INTEGRITY_RESTORE_VERIFIED_NO_PII_OUTPUT\n";
} catch (\Throwable $ex) {
    fwrite(STDERR,"BACKUP_FAILED_FAIL_CLOSED\n");exit(3);
}
