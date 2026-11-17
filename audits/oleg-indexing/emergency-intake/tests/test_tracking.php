<?php
declare(strict_types=1);
require dirname(__DIR__).'/private/intake-core.php';
use function Oleg\Emergency\{tracking,host};
function check(bool $ok,string $message):void { if(!$ok) throw new RuntimeException($message); }
$s="potrebpravo.ru";
$a=tracking(['entry'=>'homepage','utm_source'=>'yandex','utm_medium'=>'cpc','utm_campaign'=>'legal_ad'], '',$s);
check($a['site']===$s && $a['entry_hint']==='homepage','site/entry');
check($a['traffic_channel']==='unverified','no invented organic');
check($a['utm_transport']==='query' && $a['utm']['utm_campaign']==='legal_ad','valid query UTM');
$b=tracking(['entry'=>'assistant'], "https://$s/?utm_source=google&utm_medium=organic", $s);
check($b['utm_transport']==='same_site_referer' && $b['utm']['utm_medium']==='organic','observed same-host referrer UTM');
check($b['traffic_channel']==='unverified','do not infer verified channel from param');
$c=tracking(['entry'=>'unknown','utm_term'=>'alice@example.com','utm_campaign'=>'https://private.example','utm_content'=>'79991112233','utm_medium'=>'', 'utm_source'=>['array']], '',$s);
check($c['utm']===[] && $c['entry_hint']==='unknown','reject PII/malicious input');
$d=tracking(['entry'=>'homepage'], "https://$s.attacker.test/?utm_source=forged",$s);
check($d['utm']===[] && $d['utm_transport']==='none','host spoof blocked');
$e=tracking(['entry'=>'homepage'], "https://$s/?utm_term=leadref",$s);
check($e['utm']['utm_term']==='leadref','referrer accepted');
$f=tracking(['entry'=>'homepage','utm_source'=>'manual'], "https://$s/?utm_source=referrer",$s);
check($f['utm']['utm_source']==='manual' && $f['utm_transport']==='query','explicit GET wins over referer');
$_SERVER=['HTTP_HOST'=>'potrebpravo.ru','HTTPS'=>'On','SERVER_PORT'=>'80','REMOTE_ADDR'=>'192.0.2.2'];
check(host()==='potrebpravo.ru','Timeweb HTTPS On must be accepted');
$_SERVER['HTTPS']='off';
try { host(); throw new RuntimeException('HTTP was accepted unexpectedly'); }
catch (RuntimeException $ex) { check($ex->getMessage()==='HTTPS required','HTTP must be rejected'); }
echo "TRACKING_ATTRIBUTION_AND_TIMEWEB_HTTPS_TESTS_PASS\n";
