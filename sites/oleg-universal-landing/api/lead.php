<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') api_json(405, ['status'=>'method_not_allowed']);
if (stripos((string)($_SERVER['CONTENT_TYPE'] ?? ''),'application/json') !== 0) api_json(415, ['status'=>'unsupported_media_type']);
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 8192) api_json(413, ['status'=>'too_large']);
$body = json_decode(file_get_contents('php://input', false, null, 0, 8193), true);
if (!is_array($body)) api_json(400, ['status'=>'invalid_json']);
try {
    [$webhook,$category,$assigned,$expectedOrigin] = api_crm_config();
} catch (Throwable $e) { api_json(503, ['status'=>'unavailable']); }
$origin = rtrim((string)($_SERVER['HTTP_ORIGIN'] ?? ''), '/');
if (!hash_equals($expectedOrigin,$origin)) api_json(403, ['status'=>'forbidden_origin']);
api_session();
$provided = is_string($body['csrf'] ?? null) ? $body['csrf'] : '';
$stored = (string)($_SESSION['lead_nonce'] ?? '');
$issuedAt = (int)($_SESSION['lead_nonce_at'] ?? 0);
if (!$stored || !hash_equals($stored, $provided) || time() - $issuedAt > 1200 || $issuedAt > time() + 5) {
    api_json(403, ['status'=>'invalid_token']);
}
unset($_SESSION['lead_nonce'],$_SESSION['lead_nonce_at']);
session_write_close();
if (!empty($body['website'])) api_json(400, ['status'=>'invalid_submission']);
$requestId = is_string($body['request_id'] ?? null) ? $body['request_id'] : '';
if (!preg_match('/^[a-f0-9-]{36}$/i', $requestId)) api_json(422,['status'=>'invalid_request']);
$topics = ['Семейное право','Жилищные вопросы','Наследство','Недвижимость и земля','Долги и кредиты','Трудовой спор','Защита прав потребителей','Судебный спор','Другая юридическая проблема'];
$topic = api_field($body['topic'] ?? '', 100);
$name = api_field($body['name'] ?? '', 80);
$phone = api_phone((string)($body['phone'] ?? ''));
$message = api_field($body['message'] ?? '', 1000);
if (!in_array($topic, $topics, true) || mb_strlen($name) < 2 || !$phone || ($body['consent'] ?? false) !== true) {
    api_json(422,['status'=>'invalid_fields']);
}
$data = ['topic'=>$topic,'name'=>$name,'phone'=>$phone,'message'=>$message,'request_id'=>$requestId,
 'page'=>api_field($body['page'] ?? '/', 180)];
foreach (['utm_source','utm_medium','utm_campaign','utm_content','utm_term'] as $u) {
    $data[$u] = api_field($body[$u] ?? '', 150);
}
try {
    $dir = api_state_dir();
    $clientHash = hash('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    $ratePath = $dir . '/rate-' . substr($clientHash, 0, 32) . '.json';
    $rateFile = fopen($ratePath, 'c+');
    if (!$rateFile || !flock($rateFile, LOCK_EX)) throw new RuntimeException('rate limiter unavailable');
    $previous = json_decode(stream_get_contents($rateFile) ?: '[]', true);
    $recent = array_values(array_filter(is_array($previous) ? $previous : [], static fn($t) => is_int($t) && $t > time() - 600));
    if (count($recent) >= 5) { flock($rateFile, LOCK_UN); fclose($rateFile); api_json(429,['status'=>'too_many_requests']); }
    $recent[] = time(); rewind($rateFile); ftruncate($rateFile, 0); fwrite($rateFile, json_encode($recent)); fflush($rateFile);
    flock($rateFile, LOCK_UN); fclose($rateFile);
    $statePath = $dir . '/submission-' . strtolower($requestId) . '.json';
    $record = @fopen($statePath, 'x');
    if ($record === false) {
        $prior = json_decode((string)@file_get_contents($statePath), true);
        if (is_array($prior) && ($prior['status'] ?? '') === 'accepted') api_json(200,['status'=>'accepted']);
        api_json(503,['status'=>'outcome_unconfirmed']);
    }
    fwrite($record, json_encode(['status'=>'pending','at'=>time()]));
    fclose($record);
    @chmod($statePath,0600);
    $duplicate = api_crm_call($webhook, 'crm.duplicate.findbycomm', ['type'=>'PHONE','values'=>[$phone],'entity_type'=>'CONTACT']);
    $ids = is_array($duplicate) ? ($duplicate['CONTACT'] ?? []) : [];
    if (!is_array($ids)) throw new RuntimeException('unexpected duplicate search result');
    $contactId = 0;
    foreach ($ids as $candidate) {
        if (filter_var($candidate, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]])) { $contactId=(int)$candidate; break; }
    }
    if ($contactId === 0) {
        $created = api_crm_call($webhook, 'crm.contact.add', ['fields'=>[
            'NAME'=>$name,
            'PHONE'=>[['VALUE'=>$phone,'VALUE_TYPE'=>'WORK']],
            'SOURCE_DESCRIPTION'=>'Универсальный юридический лендинг'
        ]]);
        if (!filter_var($created, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]])) throw new RuntimeException('contact not confirmed');
        $contactId = (int)$created;
    }
    $fields = api_deal_fields($data, $contactId, $category, $assigned);
    $createdDeal = api_crm_call($webhook, 'crm.deal.add', ['fields'=>$fields]);
    if (!filter_var($createdDeal, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]])) throw new RuntimeException('deal not confirmed');
    $dealId = (int)$createdDeal;
    $readBack = api_crm_call($webhook, 'crm.deal.get', ['id'=>$dealId]);
    if (!is_array($readBack) || (int)($readBack['ID'] ?? 0) !== $dealId
        || (int)($readBack['CONTACT_ID'] ?? 0) !== $contactId) throw new RuntimeException('CRM readback does not match');
    $saved = @file_put_contents($statePath, json_encode(['status'=>'accepted','deal_id'=>$dealId,'at'=>time()]), LOCK_EX);
    if ($saved === false) throw new RuntimeException('receipt not persisted');
    api_json(200,['status'=>'accepted']);
} catch (Throwable $e) {
    // Never place credentials, client data or CRM response bodies in web-facing errors.
    api_json(503,['status'=>'outcome_unconfirmed']);
}
