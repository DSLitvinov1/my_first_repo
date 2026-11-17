<?php
declare(strict_types=1);
/** CLI only: privacy-preserving email alert for the operator, not CRM delivery. */
require_once __DIR__.'/intake-core.php';
use function Oleg\Emergency\db;
if (PHP_SAPI!=='cli') { http_response_code(404); exit; }
$home=$argv[1]??'';
$mode=$argv[2]??'--check';
if (!in_array($mode,['--check','--dry-run','--test-mail'],true)
    || !str_starts_with($home,'/')
    || str_contains($home,'/public_html')) { fwrite(STDERR,"INVALID_CONFIG\n");exit(2); }
const RECIPIENT = 'centr-uprav@inbox.ru'; // Operator's published contact; no applicant PII.
const FROM = 'noreply@potrebpravo.ru';
function dispatch(string $subject,string $body): bool {
    if (getenv('OLEG_ALERT_TEST_MODE')==='1') {
        $path=(string)getenv('OLEG_ALERT_TEST_SINK');
        if (!str_starts_with($path,'/tmp/oleg-v18-intake-test.')) throw new RuntimeException('Unsafe test sink');
        return file_put_contents($path,json_encode(['recipient'=>RECIPIENT,'subject'=>$subject,'body'=>$body],JSON_THROW_ON_ERROR)."\n",FILE_APPEND|LOCK_EX)!==false;
    }
    return mail(RECIPIENT,$subject,$body,[
        'From'=>FROM,'Reply-To'=>RECIPIENT,
        'Content-Type'=>'text/plain; charset=UTF-8',
        'X-Auto-Response-Suppress'=>'All'
    ]);
}
try {
    $lockPath=$home.'/alert.lock';
    $lock=@fopen($lockPath,'c');
    if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) { fwrite(STDERR,"ALERT_BUSY\n");exit(3); }
    chmod($lockPath,0600);
    $pdo=db($home);
    $pdo->exec('CREATE TABLE IF NOT EXISTS alert_state (id INTEGER PRIMARY KEY CHECK(id=1), last_count INTEGER NOT NULL, last_sent_at INTEGER NOT NULL)');
    $statement=$pdo->query("SELECT site, COUNT(*) AS total FROM requests WHERE status='awaiting_manual_review' GROUP BY site ORDER BY site");
    $rows=$statement->fetchAll(\PDO::FETCH_ASSOC);
    $count=array_sum(array_map(static fn($r)=>(int)$r['total'],$rows));
    $state=$pdo->query('SELECT last_count,last_sent_at FROM alert_state WHERE id=1')->fetch(\PDO::FETCH_ASSOC)?:['last_count'=>0,'last_sent_at'=>0];
    $needs=$count>0 && ($count>(int)$state['last_count'] || time()-(int)$state['last_sent_at']>=3600);
    if ($mode==='--dry-run') {
        echo json_encode(['pending_total'=>$count,'by_site'=>$rows,'would_alert'=>$needs,'contains_personal_data'=>false],JSON_UNESCAPED_UNICODE)."\n";exit;
    }
    if ($count===0 && (int)$state['last_count']!==0 && $mode==='--check') {
        $pdo->exec('UPDATE alert_state SET last_count=0 WHERE id=1');
    }
    if ($mode==='--test-mail') {
        $ok=dispatch('[TEST] Oleg Legal: emergency inbox alert channel',
            "Тестовое служебное сообщение.\nРеальных данных клиентов нет.\nПожалуйста, подтвердите получение отправителю.\n");
        if (!$ok) throw new RuntimeException('Mail transport unavailable');
        echo "TEST_MAIL_ACCEPTED_BY_TRANSPORT_NOT_PROOF_OF_DELIVERY\n";exit;
    }
    if (!$needs) { echo "ALERT_NOOP\n";exit; }
    $lines=["На юридических сайтах есть новые обращения, ожидающие ручной обработки.",
       "Количество: $count",
       "По сайтам:"];
    foreach ($rows as $row) $lines[]=$row['site'].': '.(int)$row['total'];
    $lines[]="Войдите в защищённую консоль Timeweb. Не отправляйте клиентские данные обычной почтой.";
    $lines[]="Это не подтверждение создания сделки в Битрикс24.";
    if (!dispatch('Oleg Legal: emergency intake needs review',implode("\n",$lines)."\n")) {
        throw new RuntimeException('Mail transport failed');
    }
    $statement=$pdo->prepare('INSERT INTO alert_state(id,last_count,last_sent_at) VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET last_count=excluded.last_count,last_sent_at=excluded.last_sent_at');
    $statement->execute([$count,time()]);
    echo "ALERT_ACCEPTED_BY_MAIL_TRANSPORT_NOT_CONFIRMED_DELIVERED\n";
} catch (\Throwable $e) {
    fwrite(STDERR,"ALERT_ERROR (no personal data in logs)\n");exit(4);
}
