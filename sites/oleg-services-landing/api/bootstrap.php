<?php
declare(strict_types=1);
// Only static, non-sensitive settings belong in the repository.
// Secrets and verified CRM routing values are supplied as server environment variables.
function api_json(int $code, array $body): never {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, private');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function api_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('OLEG_SERVICES_SESS');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'httponly' => true,
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'samesite' => 'Lax',
    ]);
    session_start();
}
function api_state_dir(): string {
    $dir = trim((string) getenv('OLEG_SERVICES_STATE_DIR'));
    if (!$dir || !str_starts_with($dir, '/') || str_contains($dir, '..')) {
        throw new RuntimeException('private state directory must be explicitly configured');
    }
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) throw new RuntimeException('private storage unavailable');
    $resolved = realpath($dir);
    $docroot = realpath((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
    if (!$resolved || !is_writable($resolved) || ($docroot && ($resolved === $docroot || str_starts_with($resolved, $docroot . '/')))) {
        throw new RuntimeException('private storage not safely located');
    }
    return $resolved;
}
function api_phone(string $raw): ?string {
    $digits = preg_replace('/\D+/', '', $raw);
    if (strlen($digits) !== 11 || !in_array($digits[0], ['7','8'], true)) return null;
    return '+7' . substr($digits, 1);
}
function api_field($value, int $max): string {
    return is_string($value) ? mb_substr(trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u',' ', $value) ?? ''), 0, $max) : '';
}
function api_crm_config(): array {
    $url = trim((string) getenv('OLEG_BITRIX_WEBHOOK_URL'));
    $category = getenv('OLEG_BITRIX_CATEGORY_ID');
    $assigned = getenv('OLEG_BITRIX_ASSIGNED_BY_ID');
    $origin = trim((string) getenv('OLEG_SERVICES_PUBLIC_ORIGIN'));
    $parts = parse_url($url);
    if (!$parts || ($parts['scheme'] ?? '') !== 'https'
        || strtolower($parts['host'] ?? '') !== 'b24-xlzm11.bitrix24.ru'
        || !preg_match('~^/rest/[0-9]+/[^/]+/?$~', $parts['path'] ?? '')
        || !ctype_digit((string) $category)
        || !ctype_digit((string) $assigned)
        || (int) $assigned < 1
        || !preg_match('~^https://[a-z0-9.-]+(?::443)?$~i', $origin)
        || preg_match('~[?#]~', $url)
    ) throw new RuntimeException('required deployment configuration missing');
    return [rtrim($url, '/') . '/', (int)$category, (int)$assigned, $origin];
}
function api_crm_call(string $root, string $method, array $params): mixed {
    $url = $root . $method . '.json';
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($params),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
    ]);
    $raw = curl_exec($ch);
    $http = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (!is_string($raw) || $http < 200 || $http >= 300) throw new RuntimeException('CRM transport error');
    $parsed = json_decode($raw, true);
    if (!is_array($parsed) || isset($parsed['error']) || !array_key_exists('result', $parsed)) {
        throw new RuntimeException('CRM rejected request');
    }
    return $parsed['result'];
}
function api_deal_fields(array $data, int $contactId, int $category, int $assigned): array {
    $labels = [
        'utm_source'=>'UTM_SOURCE','utm_medium'=>'UTM_MEDIUM','utm_campaign'=>'UTM_CAMPAIGN',
        'utm_content'=>'UTM_CONTENT','utm_term'=>'UTM_TERM'
    ];
    $serviceLabels = [
        'free'=>'Бесплатная консультация (до 8–10 минут, без анализа документов)',
        'paid'=>'Платная консультация с изучением документов',
        'documents'=>'Составление документов',
        'remote'=>'Дистанционное сопровождение',
        'turnkey'=>'Сопровождение под ключ'
    ];
    if (!isset($serviceLabels[$data['service']])) throw new RuntimeException('unknown service');
    $comments = "Источник: Второй юридический лендинг — выбор услуги\n"
        . "Формат помощи: " . $serviceLabels[$data['service']] . "\n"
        . "Код формата: " . $data['service'] . "\n"
        . "Направление: " . $data['topic'] . "\n"
        . "Сообщение: " . ($data['message'] ?: 'Не указано') . "\n"
        . "Страница: " . $data['page'] . "\n"
        . "Идентификатор обращения: " . $data['request_id']
        . (empty($data['yclid']) ? "" : "\nYandex Click ID: " . $data['yclid']);
    $fields = [
        'TITLE' => 'Юридическая помощь: ' . $serviceLabels[$data['service']] . ' — ' . $data['topic'],
        'CATEGORY_ID' => $category, 'ASSIGNED_BY_ID' => $assigned,
        'CONTACT_IDS' => [$contactId], 'COMMENTS' => $comments,
        'ORIGINATOR_ID' => 'oleg-services-landing',
        'ORIGIN_ID' => $data['request_id'],
        'SOURCE_DESCRIPTION' => 'Второй юридический лендинг — выбор услуги'
    ];
    foreach ($labels as $key => $bitrix) if ($data[$key] !== '') $fields[$bitrix] = $data[$key];
    $source = trim((string)getenv('OLEG_BITRIX_SOURCE_ID'));
    if ($source !== '') $fields['SOURCE_ID'] = $source; // Only after verifying status-list for this CRM.
    return $fields;
}

/** Search for an existing deal by durable source-specific ID before creating another one. */
function api_existing_deal(callable $call, string $requestId): ?array {
    $response = $call('crm.deal.list', [
        'filter'=>['=ORIGINATOR_ID'=>'oleg-services-landing', '=ORIGIN_ID'=>$requestId],
        'select'=>['ID','CONTACT_ID','CATEGORY_ID','ASSIGNED_BY_ID','ORIGINATOR_ID','ORIGIN_ID']
    ]);
    if (!is_array($response)) throw new RuntimeException('CRM deal search unavailable');
    if (count($response) > 1) throw new RuntimeException('multiple CRM deals for one request');
    if (!$response) return null;
    $row = $response[0];
    if (!is_array($row) || (int)($row['ID'] ?? 0) <= 0) throw new RuntimeException('unexpected deal lookup result');
    return $row;
}
function api_verify_deal(callable $call, int $dealId, int $contactId, int $category, int $assigned, string $requestId): void {
    $item = $call('crm.deal.get', ['id'=>$dealId]);
    if (!is_array($item) || (int)($item['ID'] ?? 0) !== $dealId
        || (int)($item['CONTACT_ID'] ?? 0) !== $contactId
        || (int)($item['CATEGORY_ID'] ?? -1) !== $category
        || (int)($item['ASSIGNED_BY_ID'] ?? -1) !== $assigned
        || (string)($item['ORIGINATOR_ID'] ?? '') !== 'oleg-services-landing'
        || (string)($item['ORIGIN_ID'] ?? '') !== $requestId) {
        throw new RuntimeException('CRM readback does not match submission');
    }
}
function api_resolve_deal(callable $call, array $data, int $contactId, int $category, int $assigned): int {
    $existing = api_existing_deal($call, $data['request_id']);
    if ($existing !== null) {
        $id = (int)$existing['ID'];
        api_verify_deal($call, $id, $contactId, $category, $assigned, $data['request_id']);
        return $id;
    }
    $id = $call('crm.deal.add', ['fields'=>api_deal_fields($data, $contactId, $category, $assigned)]);
    if (!filter_var($id, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]])) {
        throw new RuntimeException('CRM deal not confirmed');
    }
    api_verify_deal($call, (int)$id, $contactId, $category, $assigned, $data['request_id']);
    return (int)$id;
}
