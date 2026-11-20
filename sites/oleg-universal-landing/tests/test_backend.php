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
check($f['CONTACT_IDS'] === [42] && $f['CATEGORY_ID'] === 1 && $f['ASSIGNED_BY_ID'] === 7, 'CRM routing');
check($f['UTM_SOURCE'] === 'yandex' && $f['UTM_TERM'] === 'наследство юрист', 'CRM UTM');
check(!isset($f['UTM_CONTENT']), 'omit missing UTM');
check(str_contains($f['COMMENTS'], $data['request_id']), 'CRM idempotency marker');
$calls = [];
$mock = static function (string $method, array $params) use (&$calls): mixed {
    $calls[] = $method;
    if ($method === 'crm.deal.list') return [];
    if ($method === 'crm.deal.add') {
        if (($params['fields']['CONTACT_IDS'] ?? []) !== [42]) throw new RuntimeException('contact ids missing');
        return 321;
    }
    if ($method === 'crm.deal.get') return [
        'ID' => '321', 'CONTACT_ID' => '42', 'CATEGORY_ID' => '1',
        'ASSIGNED_BY_ID'=>'7', 'ORIGINATOR_ID'=>'oleg-universal-landing',
        'ORIGIN_ID'=>'a15e3df2-5620-4903-9df9-60c3d72f2b33'
    ];
    throw new RuntimeException('unexpected API call: ' . $method);
};
check(api_resolve_deal($mock, $data, 42, 1, 7) === 321, 'create + readback');
check($calls === ['crm.deal.list','crm.deal.add','crm.deal.get'], 'ordered transactional calls');
$found = static function (string $method, array $params) use ($mock): mixed {
    if ($method === 'crm.deal.list') return [['ID'=>'321']];
    return $mock($method, $params);
};
check(api_resolve_deal($found, $data, 42, 1, 7) === 321, 'idempotent existing deal readback');
$bad = static function (string $method, array $params) use ($mock): mixed {
    if ($method === 'crm.deal.get') return ['ID'=>'321', 'CONTACT_ID'=>'123'];
    return $mock($method, $params);
};
try { api_resolve_deal($bad, $data, 42, 1, 7); check(false,'bad readback incorrectly accepted'); }
catch (RuntimeException $e) { check(str_contains($e->getMessage(), 'readback'), 'mismatch fail closed'); }
$ambiguous = static fn(string $method,array $params): mixed => $method === 'crm.deal.list' ? [['ID'=>'1'],['ID'=>'2']] : [];
try { api_resolve_deal($ambiguous, $data, 42, 1, 7); check(false,'two deals incorrectly accepted'); }
catch (RuntimeException $e) { check(str_contains($e->getMessage(), 'multiple'), 'duplicate deal failure'); }
$store = getenv('OLEG_LANDING_STATE_DIR');
putenv('OLEG_LANDING_STATE_DIR');
try { api_state_dir(); check(false,'private directory not required'); }
catch (RuntimeException $e) { check(str_contains($e->getMessage(), 'explicitly configured'), 'private folder fail closed'); }
if ($store !== false) putenv('OLEG_LANDING_STATE_DIR='.$store);
echo "PASS: backend field validation + idempotent deal creation/readback/duplicate checks/private storage gates\n";
