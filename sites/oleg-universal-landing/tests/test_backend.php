<?php
declare(strict_types=1);
require __DIR__ . '/../api/bootstrap.php';
function check(bool $yes, string $message): void {
    if (!$yes) { fwrite(STDERR, "FAIL: ".$message."\n"); exit(1); }
}
check(api_phone('8 (917) 205-21-25') === '+79172052125', 'phone from 8');
check(api_phone('+7 (917) 205-21-25') === '+79172052125', 'phone from 7');
check(api_phone('111') === null, 'reject invalid phone');
check(api_field("  Привет\n",20) === "Привет", 'trim string');
$data = ['topic'=>'Наследство','message'=>'Нужен совет','page'=>'/',
    'request_id'=>'a15e3df2-5620-4903-9df9-60c3d72f2b33',
    'utm_source'=>'yandex','utm_medium'=>'cpc','utm_campaign'=>'search_legacy',
    'utm_content'=>'','utm_term'=>'наследство юрист'];
$f = api_deal_fields($data, 42, 1, 7);
check($f['CONTACT_ID'] === 42 && $f['CATEGORY_ID'] === 1 && $f['ASSIGNED_BY_ID'] === 7, 'CRM routing');
check($f['UTM_SOURCE'] === 'yandex' && $f['UTM_TERM'] === 'наследство юрист', 'CRM UTM');
check(!isset($f['UTM_CONTENT']), 'omit missing UTM');
check(str_contains($f['COMMENTS'], $data['request_id']), 'CRM idempotency marker');
echo "PASS: 8 backend assertions\n";
