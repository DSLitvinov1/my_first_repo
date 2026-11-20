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
$topics = ['Семейное право','Жилищные вопросы','Наследство','Недвижимость и земля','Долги и кредиты','Трудовой спор','Защита прав потребителей','Судебный спор','Арбитражные споры по договору подряда','Уголовные дела (адвокат)','Военное право','Медицинское право','Пенсионное право (перерасчёт пенсии)','Интеллектуальное право','Другая юридическая проблема'];
$topic = api_field($body['topic'] ?? '', 100);
$service = api_field($body['service'] ?? '', 20);
$services = ['free','paid','documents','remote','turnkey'];
$name = api_field($body['name'] ?? '', 80);
$phone = api_phone((string)($body['phone'] ?? ''));
$message = api_field($body['message'] ?? '', 1000);
if (!in_array($topic, $topics, true) || !in_array($service, $services, true)
    || mb_strlen($name) < 2 || !$phone || mb_strlen($message) < 5
    || ($body['consent'] ?? false) !== true) {
    api_json(422,['status'=>'invalid_fields']);
}
$data = ['topic'=>$topic,'service'=>$service,'name'=>$name,'phone'=>$phone,'message'=>$message,'request_id'=>$requestId,
 'page'=>api_field($body['page'] ?? '/', 180), 'yclid'=>api_field($body['yclid'] ?? '', 150)];
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
    $fingerprint = hash('sha256', json_encode([$data, $name, $phone], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    $record = @fopen($statePath, 'x');
    if ($record === false) {
        $prior = json_decode((string)@file_get_contents($statePath), true);
        if (!is_array($prior) || !hash_equals((string)($prior['digest'] ?? ''), $fingerprint)) {
            api_json(409, ['status'=>'request_conflict']);
        }
        if (($prior['status'] ?? '') === 'accepted') api_json(200,['status'=>'accepted']);
        // Never retry creating a deal after uncertain transport outcome.
        // Reconcile by immutable source ID if contact was already established.
        $savedContact = (int)($prior['contact_id'] ?? 0);
        if ($savedContact > 0) {
            $call = static fn(string $method, array $params) => api_crm_call($webhook, $method, $params);
            $found = api_existing_deal($call, $requestId);
            if ($found !== null) {
                $foundId = (int)$found['ID'];
                api_verify_deal($call, $foundId, $savedContact, $category, $assigned, $requestId);
                $receipt = ['status'=>'accepted','digest'=>$fingerprint,'deal_id'=>$foundId,'at'=>time()];
                if (@file_put_contents($statePath, json_encode($receipt), LOCK_EX) === false) {
                    api_json(503,['status'=>'outcome_unconfirmed']);
                }
                api_json(200,['status'=>'accepted']);
            }
        }
        api_json(503,['status'=>'outcome_unconfirmed']);
    }
    fwrite($record, json_encode(['status'=>'pending','digest'=>$fingerprint,'at'=>time()]));
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
            'SOURCE_DESCRIPTION'=>'Второй юридический лендинг — выбор услуги'
        ]]);
        if (!filter_var($created, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]])) throw new RuntimeException('contact not confirmed');
        $contactId = (int)$created;
    }
    $pending = @file_put_contents($statePath, json_encode(['status'=>'pending','digest'=>$fingerprint,'contact_id'=>$contactId,'at'=>time()]), LOCK_EX);
    if ($pending === false) throw new RuntimeException('pending contact receipt not persisted');
    $call = static fn(string $method, array $params) => api_crm_call($webhook, $method, $params);
    $dealId = api_resolve_deal($call, $data, $contactId, $category, $assigned);
    $saved = @file_put_contents($statePath, json_encode(['status'=>'accepted','digest'=>$fingerprint,'deal_id'=>$dealId,'at'=>time()]), LOCK_EX);
    if ($saved === false) throw new RuntimeException('receipt not persisted');
    api_json(200,['status'=>'accepted']);
} catch (Throwable $e) {
    // Never place credentials, client data or CRM response bodies in web-facing errors.
    api_json(503,['status'=>'outcome_unconfirmed']);
}
