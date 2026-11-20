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
    session_name('OLEG_LANDING_SESS');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'httponly' => true,
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'samesite' => 'Lax',
    ]);
    session_start();
}
function api_state_dir(): string {
    $dir = getenv('OLEG_LANDING_STATE_DIR') ?: sys_get_temp_dir() . '/oleg-landing-state-v1';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) throw new RuntimeException('private storage unavailable');
    if (!is_writable($dir)) throw new RuntimeException('private storage not writable');
    return $dir;
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
    $origin = trim((string) getenv('OLEG_LANDING_PUBLIC_ORIGIN'));
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
    $comments = "Источник: Универсальный юридический лендинг\n"
        . "Направление: " . $data['topic'] . "\n"
        . "Сообщение: " . ($data['message'] ?: 'Не указано') . "\n"
        . "Страница: " . $data['page'] . "\n"
        . "Идентификатор обращения: " . $data['request_id'];
    $fields = [
        'TITLE' => 'Юридическая помощь — ' . $data['topic'],
        'CATEGORY_ID' => $category, 'ASSIGNED_BY_ID' => $assigned,
        'CONTACT_ID' => $contactId, 'COMMENTS' => $comments,
        'ORIGINATOR_ID' => 'oleg-universal-landing',
        'ORIGIN_ID' => $data['request_id'],
        'SOURCE_DESCRIPTION' => 'Отдельный универсальный юридический лендинг'
    ];
    foreach ($labels as $key => $bitrix) if ($data[$key] !== '') $fields[$bitrix] = $data[$key];
    $source = trim((string)getenv('OLEG_BITRIX_SOURCE_ID'));
    if ($source !== '') $fields['SOURCE_ID'] = $source; // Only after verifying status-list for this CRM.
    return $fields;
}
