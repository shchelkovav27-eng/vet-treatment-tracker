<?php
// Suppress all PHP errors/warnings from polluting JSON output
error_reporting(0);
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ob_start(); // Buffer any accidental output
// ============================================================
// КОНУРА — REST API
// База: MySQL (параметры подключения — в config.php, см. config.example.php)
// ============================================================

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Token');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

// ── DB CONNECTION ─────────────────────────────────────────────
// Доступы и секреты читаются ТОЛЬКО из config.php (в git не попадает,
// шаблон — config.example.php). Сначала ищем файл выше веб-корня, затем рядом.
// Встроенных значений по умолчанию нет намеренно: без конфига API честно
// отвечает 500, а не пытается подключиться с «запасным» паролем.
// Читаем через try/@: на shared-хостинге is_readable() может вернуть true,
// а открытие всё равно упасть по правам или open_basedir.
$cfg = [];
foreach ([__DIR__ . '/../config.php', __DIR__ . '/config.php'] as $cfgPath) {
    if (!file_exists($cfgPath)) continue;
    try {
        $loaded = @include $cfgPath;
        if (is_array($loaded) && $loaded) { $cfg = $loaded; break; }
    } catch (Throwable $e) { /* пробуем следующий путь */ }
}
foreach (['db_host', 'db_name', 'db_user', 'db_pass'] as $required) {
    if (!isset($cfg[$required])) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Server is not configured: copy config.example.php to config.php'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

define('DB_HOST',    $cfg['db_host']);
define('DB_NAME',    $cfg['db_name']);
define('DB_USER',    $cfg['db_user']);
define('DB_PASS',    $cfg['db_pass']);
define('DB_CHARSET', 'utf8mb4');
define('CONFIG_EXTERNAL', true);

function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_TIMEOUT            => 30,
        ]);
        $pdo->exec("SET SESSION MAX_EXECUTION_TIME=30000");
    }
    return $pdo;
}

function ok($data, int $code = 200): void {
    if (ob_get_level()) ob_end_clean();
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['success' => true, 'data' => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function err(string $msg, int $code = 400): void {
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

function body(): array {
    $raw = file_get_contents('php://input');
    return json_decode($raw, true) ?? [];
}

// ══════════════════════════════════════════════════════════════
// ПАРОЛИ
// ══════════════════════════════════════════════════════════════
// В базе лежат SHA-256 без соли — такие подбираются по готовым таблицам
// за секунды. Переходим на password_hash (bcrypt), но БЕЗ сброса паролей:
// старый формат продолжает приниматься, а при первом успешном входе хеш
// молча пересчитывается в新 формат. Через несколько дней старых не останется.
function hashPassword(string $plain): string {
    return password_hash($plain, PASSWORD_DEFAULT);
}

function isLegacyHash(string $stored): bool {
    // bcrypt/argon начинаются с $, SHA-256 — это 64 hex-символа
    return $stored !== '' && $stored[0] !== '$';
}

function verifyPassword(string $plain, string $stored): bool {
    if ($stored === '') return false;
    if (isLegacyHash($stored)) return hash_equals($stored, hash('sha256', $plain));
    return password_verify($plain, $stored);
}

// Кириллица → латиница для автогенерации логина из ФИО.
// Раньше здесь вызывалась функция transliterate(), которой не существует,
// из-за чего создание пользователя падало с фатальной ошибкой.
function makeUsername(string $name): string {
    $map = [
        'а'=>'a','б'=>'b','в'=>'v','г'=>'g','д'=>'d','е'=>'e','ё'=>'e','ж'=>'zh',
        'з'=>'z','и'=>'i','й'=>'y','к'=>'k','л'=>'l','м'=>'m','н'=>'n','о'=>'o',
        'п'=>'p','р'=>'r','с'=>'s','т'=>'t','у'=>'u','ф'=>'f','х'=>'h','ц'=>'ts',
        'ч'=>'ch','ш'=>'sh','щ'=>'shch','ъ'=>'','ы'=>'y','ь'=>'','э'=>'e','ю'=>'yu','я'=>'ya',
    ];
    // Берём только первое слово (фамилию) — как у существующих логинов вида "ivanova".
    $first = preg_split('/\s+/u', trim($name))[0] ?? '';
    $latin = strtr(mb_strtolower($first, 'UTF-8'), $map);
    $latin = preg_replace('/[^a-z0-9]/', '', $latin);
    return $latin !== '' ? $latin : 'user';
}

// Гарантирует, что логин не повторится: authHandler ищет пользователя по
// username, поэтому два одинаковых логина сделали бы вход неоднозначным.
function uniqueUsername(PDO $db, string $base): string {
    $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE username=?");
    $candidate = $base;
    for ($i = 2; $i < 100; $i++) {
        $stmt->execute([$candidate]);
        if ((int)$stmt->fetchColumn() === 0) return $candidate;
        $candidate = $base . $i;
    }
    return $base . bin2hex(random_bytes(3));
}

// Единая точка записи в журнал. Автор берётся из токена, а не из тела запроса.
// Сбой журнала не должен ронять само действие — поэтому try/catch.
function logAudit(PDO $db, string $type, string $description, ?string $targetId, ?string $targetName, string $targetType): void {
    try {
        $u = currentUser();
        $db->prepare("INSERT INTO audit_logs (id,action_type,description,target_id,target_name,target_type,user_id,user_name,timestamp) VALUES (?,?,?,?,?,?,?,?,NOW())")
           ->execute([bin2hex(random_bytes(16)), $type, $description, $targetId, $targetName, $targetType, $u['id'] ?? null, $u['name'] ?? null]);
    } catch (Exception $e) { /* журнал не критичен */ }
}

function decodeJson(?string $v): mixed {
    if ($v === null) return null;
    $decoded = json_decode($v, true);
    return $decoded;
}

// ══════════════════════════════════════════════════════════════
// АУТЕНТИФИКАЦИЯ
// ══════════════════════════════════════════════════════════════
// AUTH_ENFORCE — рубильник проверки токена.
//   false — токен читается и логируется, но доступ НЕ блокируется (режим наблюдения).
//   true  — без валидного токена API отдаёт 401.
// Порядок включения: задеплоить с false → открыть ?r=whoami в браузере
// под залогиненным пользователем → убедиться, что token_received=true
// и user не null → только тогда переключить на true и задеплоить снова.
define('AUTH_ENFORCE', true);

define('TOKEN_SALT', (string)($cfg['token_salt'] ?? ''));

// Ключ для планировщика: задачи надо досоздавать даже когда в приложение
// никто не заходил, а у cron нет пользовательского токена.
// Пустой ключ = вход планировщика по ключу выключен (hash_equals('', …) не пройдёт).
define('MAINT_KEY', (string)($cfg['maint_key'] ?? ''));

// Достаём токен из всех возможных мест: shared-хостинг может резать
// кастомные заголовки, поэтому цепочка фолбэков, а не один источник.
function bearerToken(): ?string {
    if (!empty($_SERVER['HTTP_X_TOKEN']))          return $_SERVER['HTTP_X_TOKEN'];
    if (!empty($_SERVER['REDIRECT_HTTP_X_TOKEN'])) return $_SERVER['REDIRECT_HTTP_X_TOKEN'];
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) {
            if (strcasecmp($k, 'X-Token') === 0 && $v !== '') return $v;
        }
    }
    if (!empty($_GET['token'])) return $_GET['token'];   // autoLogin() шлёт токен в query
    return null;
}

// Токены старого образца = sha256(id + общая соль). Они одинаковы всегда и
// у всех, их нельзя ни отозвать, ни просрочить: украли — доступ навсегда.
// Новые привязаны к личному секрету пользователя, смена секрета мгновенно
// обрывает все его сессии. Старые принимаются до этой даты, чтобы никого
// не выкинуть из системы посреди рабочего дня.
define('LEGACY_TOKEN_UNTIL', '2026-07-28');

function ensureTokenSecretColumn(PDO $db): void {
    static $done = false;
    if ($done) return;
    $done = true;
    $has = $db->query("SELECT COUNT(*) FROM information_schema.columns
                       WHERE table_schema=DATABASE() AND table_name='users' AND column_name='token_secret'")->fetchColumn();
    if (!$has) $db->exec("ALTER TABLE users ADD COLUMN token_secret VARCHAR(64) NULL");
}

function makeToken(string $userId, ?string $secret): string {
    return $secret ? hash('sha256', $userId . ':' . $secret) : hash('sha256', $userId . TOKEN_SALT);
}

// Выдаёт пользователю личный секрет, если его ещё нет, и возвращает токен.
function issueToken(PDO $db, array $user): string {
    ensureTokenSecretColumn($db);
    $secret = $user['token_secret'] ?? null;
    if (!$secret) {
        $secret = bin2hex(random_bytes(24));
        $db->prepare("UPDATE users SET token_secret=? WHERE id=?")->execute([$secret, $user['id']]);
    }
    return makeToken($user['id'], $secret);
}

// Обрывает все сессии пользователя: меняем секрет — выданные токены мертвы.
function revokeTokens(PDO $db, string $userId): void {
    ensureTokenSecretColumn($db);
    $db->prepare("UPDATE users SET token_secret=? WHERE id=?")->execute([bin2hex(random_bytes(24)), $userId]);
}

// Возвращает пользователя по токену или null. Результат кешируется на запрос.
function currentUser(): ?array {
    static $resolved = false, $user = null;
    if ($resolved) return $user;
    $resolved = true;

    $token = bearerToken();
    if (!$token) return $user = null;

    $db = db();
    ensureTokenSecretColumn($db);
    $legacyOk = date('Y-m-d') <= LEGACY_TOKEN_UNTIL;

    // Обратной функции у хеша нет, поэтому сверяем перебором по активным
    // пользователям — их два десятка, это дёшево.
    $rows = $db->query("SELECT id,name,email,username,role,is_active,token_secret FROM users WHERE is_active=1")->fetchAll();
    foreach ($rows as $u) {
        if ($u['token_secret'] && hash_equals(makeToken($u['id'], $u['token_secret']), $token)) {
            unset($u['token_secret']);
            return $user = $u;
        }
        if ($legacyOk && hash_equals(hash('sha256', $u['id'] . TOKEN_SALT), $token)) {
            unset($u['token_secret']);
            return $user = $u;
        }
    }
    return $user = null;
}

// Требует любого залогиненного пользователя.
function requireAuth(): array {
    $u = currentUser();
    if (!$u) {
        if (!AUTH_ENFORCE) return ['id'=>null,'role'=>'anonymous','name'=>'anonymous'];
        err('Требуется авторизация', 401);
    }
    return $u;
}

// Требует одну из перечисленных ролей.
function requireRole(array $roles): array {
    $u = requireAuth();
    if (!AUTH_ENFORCE) return $u;
    if (!in_array($u['role'], $roles, true)) err('Недостаточно прав', 403);
    return $u;
}

// Диагностика: доходит ли токен до сервера. Ничего не меняет и не раскрывает
// чужих данных — только факт распознавания текущего токена.
function whoamiHandler(): void {
    $token = bearerToken();
    $u = currentUser();
    ok([
        'auth_enforce'    => AUTH_ENFORCE,
        'token_received'  => $token !== null,
        'token_source'    => !empty($_SERVER['HTTP_X_TOKEN']) ? 'header'
                             : (!empty($_GET['token']) ? 'query' : 'none'),
        'token_valid'     => $u !== null,
        'user'            => $u ? ['name'=>$u['name'],'role'=>$u['role']] : null,
    ]);
}

// ── ROUTER ────────────────────────────────────────────────────
$method   = $_SERVER['REQUEST_METHOD'];
$resource = $_GET['r'] ?? '';
$id       = $_GET['id'] ?? null;

try {
    route($method, $resource, $id);
} catch (PDOException $e) {
    err('DB error: ' . $e->getMessage(), 500);
} catch (Exception $e) {
    err($e->getMessage(), 500);
}

// ══════════════════════════════════════════════════════════════
function route(string $method, string $resource, ?string $id): void {
    // Публичные эндпоинты: вход, автовход и smoke-тест деплоя.
    // Всё остальное — только с валидным токеном.
    $public = ['auth', 'verify', 'debug', 'whoami'];

    // Досоздание задач запускается либо планировщиком по ключу, либо
    // приложением от имени вошедшего пользователя.
    if ($resource === 'maintenance' && ($_GET['key'] ?? '') !== '' && hash_equals(MAINT_KEY, $_GET['key'])) {
        maintenanceHandler();
        return;
    }

    if (!in_array($resource, $public, true)) {
        $isWrite = in_array($method, ['POST', 'PUT', 'DELETE'], true);
        // Роли по документации: techAdmin — всё; doctor — все разделы;
        // shelterAdmin — только животные; executor — только отметка задач.
        match(true) {
            // Читать список сотрудников может любой авторизованный: форма
            // назначения подставляет туда врачей. Пароли эндпоинт не отдаёт.
            // Заводить и менять пользователей — только techAdmin.
            $resource === 'users' && $isWrite         => requireRole(['techAdmin','doctor']),
            $resource === 'animals'    && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'routes'     && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'places'     && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'procedures' && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'analytics'                => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'export'                   => requireRole(['techAdmin','doctor','shelterAdmin']),
            // История выдачи и сводка по сотрудникам — рабочие инструменты
            // старшего смены, поэтому доступны и администратору приюта.
            $resource === 'history'                  => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'staff'                    => requireRole(['techAdmin','doctor','shelterAdmin']),
            // Журнал изменений — только техадмину: там видно все действия всех.
            $resource === 'audit'                    => requireRole(['techAdmin','doctor','shelterAdmin']),
            // Справочник читают все (он подставляется в форму назначения),
            // а править и проверять дубли — все, кроме исполнителей.
            $resource === 'templates' && $isWrite    => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'med_duplicates'           => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'dupes'                    => requireRole(['techAdmin','doctor','shelterAdmin']),
            // Слияние правит ссылки по всей базе. Даём тем же ролям, что уже
            // могут переименовать место с переносом животных, — иначе выходит
            // непоследовательно: одно и то же действие то можно, то нельзя.
            $resource === 'dict_merge'               => requireRole(['techAdmin','doctor','shelterAdmin']),
            // Пристройство ведут админы приюта и врачи; исполнителям не нужно.
            $resource === 'placement'   && $isWrite  => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'pl_statuses' && $isWrite  => requireRole(['techAdmin','doctor','shelterAdmin']),
            // Вакцинации вносят врачи и ассистенты; справочник типов — врачи и техадмин.
            $resource === 'vacc'       && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            // Медицинские записи вносят те же, кто ведёт лечение.
            $resource === 'hvi'        && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'steril'     && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'donations'  && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'vacc_types' && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            // Диагнозы читают все (подставляются в форму лечения), правят — врачи и админы.
            $resource === 'diagnoses'  && $isWrite   => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'vacc_report'              => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'outcomes'                 => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'channels'    && $isWrite  => requireRole(['techAdmin','doctor','shelterAdmin']),
            $resource === 'listings'    && $isWrite  => requireRole(['techAdmin','doctor','shelterAdmin']),
            default                                  => requireAuth(),
        };
    }

    match($resource) {
        'routes'        => routesHandler($method, $id),
        'places'        => placesHandler($method, $id),
        'animals'       => animalsHandler($method, $id),
        'procedures'    => proceduresHandler($method, $id),
        'tasks'         => tasksHandler($method, $id),
        'users'         => usersHandler($method, $id),
        'stats'         => statsHandler(),
        'analytics'     => analyticsHandler(),
        'history'       => historyHandler(),
        'audit'         => auditHandler(),
        'staff'         => staffHandler(),
        'maintenance'   => maintenanceHandler(),
        'templates'     => templatesHandler($method, $id),
        'placement'     => placementHandler($method, $id),
        'pl_statuses'   => placementStatusesHandler($method, $id),
        'vacc'          => vaccinationsHandler($method, $id),
        'vacc_types'    => vaccTypesHandler($method, $id),
        'diagnoses'     => diagnosesHandler($method, $id),
        'vacc_report'   => vaccReportHandler(),
        'hvi'           => hviHandler($method, $id),
        'steril'        => sterilHandler($method, $id),
        'donations'     => donationsHandler($method, $id),
        'outcomes'      => outcomeReportHandler(),
        'channels'      => channelsHandler($method, $id),
        'listings'      => listingsHandler($method, $id),
        'med_duplicates'=> medDuplicatesHandler(),
        'dupes'         => dictDuplicatesHandler(),
        'dict_merge'    => dictMergeHandler(),
        'export'        => exportHandler(),
        'auth'          => authHandler($method),
        'verify'        => verifyHandler(),
        'whoami'        => whoamiHandler(),
        'debug'         => debugHandler(),
        default         => err('Unknown endpoint: ' . $resource, 404),
    };
}

// ══════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════
function ensureRouteColumns(PDO $db): void {
    static $done = false;
    if ($done) return;
    $done = true;
    $cols = $db->query("SHOW COLUMNS FROM routes")->fetchAll(PDO::FETCH_COLUMN);
    $add = [
        'color'      => "VARCHAR(20) DEFAULT '#9E9E9E'",
        'sort_order' => 'INT DEFAULT 0',
        'is_active'  => 'TINYINT(1) DEFAULT 1',
        'capacity'   => 'INT NULL',
    ];
    foreach ($add as $c => $type) {
        if (!in_array($c, $cols, true)) $db->exec("ALTER TABLE routes ADD COLUMN `$c` $type");
    }
    // Первичная расстановка порядка, чтобы существующие маршруты не смешались.
    if (!in_array('sort_order', $cols, true)) {
        $i = 10;
        foreach ($db->query("SELECT id FROM routes ORDER BY name")->fetchAll(PDO::FETCH_COLUMN) as $rid) {
            $db->prepare("UPDATE routes SET sort_order=? WHERE id=?")->execute([$i, $rid]);
            $i += 10;
        }
    }
}

// ══════════════════════════════════════════════════════════════
// МЕСТА ВНУТРИ МАРШРУТА
// ══════════════════════════════════════════════════════════════
// Плоский список на маршрут, а не жёсткая иерархия «отделение → комната →
// бокс»: у Карантина это кабинеты, у Лишая — ярусы стеллажа, у Собачника —
// вольеры и «Коридор гуси». Навязывать одну структуру всем нельзя.
function ensurePlacesTable(PDO $db): void {
    static $done = false;
    if ($done) return;
    $done = true;
    $db->exec("CREATE TABLE IF NOT EXISTS places (
        id VARCHAR(36) PRIMARY KEY,
        route_id VARCHAR(36) NOT NULL,
        name VARCHAR(150) NOT NULL,
        capacity INT NULL,
        note VARCHAR(255) NULL,
        sort_order INT DEFAULT 0,
        is_active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT NOW(),
        UNIQUE KEY uniq_route_name (route_id, name),
        KEY idx_route (route_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function placesHandler(string $method, ?string $id): void {
    $db = db();
    ensurePlacesTable($db);

    if ($method === 'GET') {
        // Разовое наполнение из того, что уже вписано руками. Названия
        // схлопываем по регистру и пробелам — иначе «Травма 2» и «Травма2»
        // приедут в справочник как два разных места.
        if (($_GET['action'] ?? '') === 'seed') {
            requireRole(['techAdmin', 'doctor', 'shelterAdmin']);
            $rows = $db->query("SELECT route_id, TRIM(room) AS room, COUNT(*) AS cnt
                                FROM animals
                                WHERE is_active=1 AND room IS NOT NULL AND TRIM(room)<>''
                                GROUP BY route_id, TRIM(room)")->fetchAll();
            $byKey = [];
            foreach ($rows as $r) {
                $norm = mb_strtolower(preg_replace('/\s+/u', ' ', trim($r['room'])), 'UTF-8');
                $key  = $r['route_id'] . '|' . $norm;
                // Из вариантов написания берём тот, что встречается чаще.
                if (!isset($byKey[$key]) || $r['cnt'] > $byKey[$key]['cnt']) {
                    $byKey[$key] = ['route_id' => $r['route_id'], 'name' => trim($r['room']), 'cnt' => (int)$r['cnt']];
                } else {
                    $byKey[$key]['cnt'] += (int)$r['cnt'];
                }
            }
            $ins = $db->prepare("INSERT IGNORE INTO places (id,route_id,name,sort_order) VALUES (?,?,?,?)");
            $added = 0; $i = 10;
            foreach ($byKey as $v) {
                $ins->execute([bin2hex(random_bytes(16)), $v['route_id'], $v['name'], $i]);
                $added += $ins->rowCount(); $i += 10;
            }
            ok(['created' => $added, 'merged_from' => count($rows), 'unique' => count($byKey)]);
        }

        $where = ['p.is_active=1']; $params = [];
        if (!empty($_GET['route_id'])) { $where[] = 'p.route_id=?'; $params[] = $_GET['route_id']; }
        $stmt = $db->prepare("SELECT p.*, r.name AS route_name,
                                     (SELECT COUNT(*) FROM animals a
                                      WHERE a.is_active=1 AND a.route_id=p.route_id AND TRIM(a.room)=p.name) AS occupied
                              FROM places p LEFT JOIN routes r ON p.route_id=r.id
                              WHERE " . implode(' AND ', $where) . "
                              ORDER BY r.sort_order, p.sort_order, p.name");
        $stmt->execute($params);
        ok($stmt->fetchAll());
    }

    if ($method === 'POST') {
        $b = body();
        if (empty($b['route_id']) || empty($b['name'])) err('Не указан маршрут или название места');
        $newId = bin2hex(random_bytes(16));
        $max = $db->prepare("SELECT COALESCE(MAX(sort_order),0) FROM places WHERE route_id=?");
        $max->execute([$b['route_id']]);
        $db->prepare("INSERT INTO places (id,route_id,name,capacity,note,sort_order) VALUES (?,?,?,?,?,?)
                      ON DUPLICATE KEY UPDATE is_active=1, capacity=VALUES(capacity), note=VALUES(note)")
           ->execute([$newId, $b['route_id'], trim($b['name']), $b['capacity'] ?: null,
                      $b['note'] ?: null, $b['sort_order'] ?? ((int)$max->fetchColumn() + 10)]);
        ok(['id' => $newId], 201);
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        $cur = $db->prepare("SELECT * FROM places WHERE id=?");
        $cur->execute([$id]);
        $before = $cur->fetch();
        if (!$before) err('Место не найдено', 404);

        $set = []; $params = [];
        foreach (['name','capacity','note','sort_order','is_active'] as $c) {
            if (array_key_exists($c, $b)) { $set[] = "`$c`=?"; $params[] = $b[$c] === '' ? null : $b[$c]; }
        }
        if (!$set) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE places SET " . implode(',', $set) . " WHERE id=?")->execute($params);

        // Переименование места переносим и на животных: иначе они останутся
        // со старым текстом и выпадут из списка этого места.
        $moved = 0;
        if (!empty($b['rename_animals']) && !empty($b['name']) && $b['name'] !== $before['name']) {
            $u = $db->prepare("UPDATE animals SET room=? WHERE route_id=? AND TRIM(room)=?");
            $u->execute([trim($b['name']), $before['route_id'], $before['name']]);
            $moved = $u->rowCount();
        }
        ok(['updated' => true, 'animals_moved' => $moved]);
    }

    if ($method === 'DELETE' && $id) {
        $p = $db->prepare("SELECT route_id, name FROM places WHERE id=?");
        $p->execute([$id]);
        $pl = $p->fetch();
        if ($pl) {
            $c = $db->prepare("SELECT COUNT(*) FROM animals WHERE is_active=1 AND route_id=? AND TRIM(room)=?");
            $c->execute([$pl['route_id'], $pl['name']]);
            $n = (int)$c->fetchColumn();
            if ($n > 0) err("В этом месте $n живот. Сначала переведите их.");
        }
        $db->prepare("UPDATE places SET is_active=0 WHERE id=?")->execute([$id]);
        ok(['archived' => true]);
    }

    err('Method not allowed', 405);
}

function routesHandler(string $method, ?string $id): void {
    $db = db();
    ensureRouteColumns($db);

    if ($method === 'GET') {
        // include_archived=1 нужен только экрану управления маршрутами.
        $where = empty($_GET['include_archived']) ? 'WHERE is_active=1' : '';
        $rows = $db->query("SELECT * FROM routes $where ORDER BY sort_order, name")->fetchAll();
        foreach ($rows as &$r) {
            $stmt = $db->prepare("SELECT COUNT(*) FROM animals WHERE route_id=? AND is_active=1");
            $stmt->execute([$r['id']]);
            $r['animal_count'] = (int)$stmt->fetchColumn();
            $stmt2 = $db->prepare("SELECT COUNT(*) FROM procedures p JOIN animals a ON p.animal_id=a.id
                                   WHERE a.route_id=? AND a.is_active=1
                                     AND (p.course_end_date IS NULL OR p.course_end_date >= CURDATE())");
            $stmt2->execute([$r['id']]);
            $r['procedure_count'] = (int)$stmt2->fetchColumn();
        }
        ok($rows);
    }

    if ($method === 'POST') {
        $b = body();
        if (empty($b['name'])) err('Не указано название маршрута');
        $dup = $db->prepare("SELECT COUNT(*) FROM routes WHERE name=?");
        $dup->execute([trim($b['name'])]);
        if ((int)$dup->fetchColumn() > 0) err('Маршрут «' . $b['name'] . '» уже существует');

        // id строковый: у существующих это '1'..'4', у новых — uuid-подобный.
        $newId = bin2hex(random_bytes(16));
        $max = (int)$db->query("SELECT COALESCE(MAX(sort_order),0) FROM routes")->fetchColumn();
        $db->prepare("INSERT INTO routes (id,name,description,color,sort_order,is_active,capacity) VALUES (?,?,?,?,?,1,?)")
           ->execute([$newId, trim($b['name']), $b['description'] ?: null,
                      $b['color'] ?: '#9E9E9E', $b['sort_order'] ?? $max + 10, $b['capacity'] ?: null]);
        logAudit($db, 'other', 'Добавлен маршрут «' . $b['name'] . '»', $newId, $b['name'], 'route');
        ok(['id' => $newId], 201);
    }

    if ($method === 'PUT' && $id) {
        $b = body();

        // Возврат из архива
        if (array_key_exists('is_active', $b)) {
            $on = (int)$b['is_active'] === 1;
            $nm = $db->prepare("SELECT name FROM routes WHERE id=?"); $nm->execute([$id]);
            $name = (string)($nm->fetchColumn() ?: '');
            $db->prepare("UPDATE routes SET is_active=? WHERE id=?")->execute([$on ? 1 : 0, $id]);
            logAudit($db, 'other', ($on ? 'Маршрут возвращён из архива: ' : 'Маршрут убран в архив: ') . $name, $id, $name, 'route');
            ok(['updated' => true]);
        }

        if (array_key_exists('name', $b) && $b['name'] !== '') {
            $dup = $db->prepare("SELECT COUNT(*) FROM routes WHERE name=? AND id<>?");
            $dup->execute([trim($b['name']), $id]);
            if ((int)$dup->fetchColumn() > 0) err('Маршрут с таким названием уже есть');
        }
        $set = []; $params = [];
        foreach (['name','description','color','sort_order','capacity'] as $c) {
            if (array_key_exists($c, $b)) { $set[] = "`$c`=?"; $params[] = $b[$c] === '' ? null : $b[$c]; }
        }
        if (!$set) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE routes SET " . implode(',', $set) . " WHERE id=?")->execute($params);
        ok(['updated' => true]);
    }

    if ($method === 'DELETE' && $id) {
        // Маршрут не удаляем физически: на него ссылаются животные и вся
        // история задач. Убираем в архив, и только если он пуст.
        $c = $db->prepare("SELECT COUNT(*) FROM animals WHERE route_id=? AND is_active=1");
        $c->execute([$id]);
        $n = (int)$c->fetchColumn();
        if ($n > 0) err("На маршруте $n активных живот. Сначала переведите их на другой маршрут.");

        $nm = $db->prepare("SELECT name FROM routes WHERE id=?"); $nm->execute([$id]);
        $name = (string)($nm->fetchColumn() ?: '');
        $db->prepare("UPDATE routes SET is_active=0 WHERE id=?")->execute([$id]);
        logAudit($db, 'other', 'Маршрут убран в архив: ' . $name, $id, $name, 'route');
        ok(['archived' => true]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// ANIMALS
// ══════════════════════════════════════════════════════════════
function animalsHandler(string $method, ?string $id): void {
    $db = db();
    ensureVaccinationTables($db);   // здесь же заводятся поля карточки и выбытия

    if ($method === 'GET') {
        if ($id) {
            $stmt = $db->prepare("SELECT a.*, r.name as route_name FROM animals a LEFT JOIN routes r ON a.route_id=r.id WHERE a.id=?");
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            if (!$row) err('Animal not found', 404);
            ok($row);
        }

        // List with filters
        $where = [];
        $params = [];

        $active = $_GET['active'] ?? null;
        if ($active !== null) {
            $where[] = 'a.is_active = ?';
            $params[] = $active === 'false' ? 0 : 1;
        } else {
            $where[] = 'a.is_active = 1';
        }

        if (!empty($_GET['route_id'])) {
            // Accept both numeric id and route name
            $routeVal = $_GET['route_id'];
            if (is_numeric($routeVal)) {
                $where[] = 'a.route_id = ?';
                $params[] = $routeVal;
            } else {
                // Find by name
                $rStmt = $db->prepare("SELECT id FROM routes WHERE name=?");
                $rStmt->execute([$routeVal]);
                $rRow = $rStmt->fetch();
                if ($rRow) { $where[] = 'a.route_id = ?'; $params[] = $rRow['id']; }
            }
        }
        if (!empty($_GET['search'])) {
            $where[] = 'a.name LIKE ?';
            $params[] = '%' . $_GET['search'] . '%';
        }
        if (!empty($_GET['status'])) {
            $where[] = 'a.status = ?';
            $params[] = $_GET['status'];
        }

        $sql = "SELECT a.*, r.name as route_name
            FROM animals a
            LEFT JOIN routes r ON a.route_id=r.id";
        if ($where) $sql .= ' WHERE ' . implode(' AND ', $where);
        $sql .= ' ORDER BY a.name';

        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        // Add active procedure count per animal (batch query)
        if ($rows) {
            $ids = array_column($rows, 'id');
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $pcStmt = $db->prepare(
                "SELECT animal_id, COUNT(*) as cnt FROM procedures 
                WHERE animal_id IN ($placeholders) 
                AND (course_end_date IS NULL OR course_end_date >= CURDATE())
                GROUP BY animal_id"
            );
            $pcStmt->execute($ids);
            $pcMap = [];
            foreach ($pcStmt->fetchAll() as $pc) {
                $pcMap[$pc['animal_id']] = $pc['cnt'];
            }
            foreach ($rows as &$row) {
                $row['active_procedures'] = $pcMap[$row['id']] ?? 0;
            }
        }

        ok($rows);
    }

    if ($method === 'POST') {
        $b = body();
        $id = $b['id'] ?? bin2hex(random_bytes(16));
        if (empty($b['name'])) err('Не указана кличка');
        $stmt = $db->prepare("INSERT INTO animals (id,name,species,gender,route_id,room,cage_number,status,is_active,notes,allergies,photo_url) VALUES (?,?,?,?,?,?,?,?,1,?,?,?)");
        $stmt->execute([$id, $b['name'], $b['species']??'cat', $b['gender']??'unknown', $b['route_id']??null, $b['room']??null, $b['cage_number']??null, $b['status']??'stable', $b['notes']??null, $b['allergies']??null, $b['photo_url']??null]);
        // Задачи здесь НЕ генерируются: они порождаются назначением (procedures),
        // а не самим фактом появления животного. Раньше сюда был скопирован
        // вызов generateTasksForProcedure с id животного вместо id назначения.
        logAudit($db, 'animalCreated', 'Добавлено животное: ' . $b['name'], $id, $b['name'], 'animal');
        ok(['id' => $id], 201);
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        $fields = [];
        $params = [];
        foreach (['name','species','gender','route_id','room','cage_number','status','is_active','notes','hiv_status','leukemia_status','blood_type','allergies','birth_date','breed','color','chip_number','lab_number','weight'] as $f) {
            if (array_key_exists($f, $b)) {
                $fields[] = "`$f`=?";
                $params[] = $b[$f];
            }
        }
        if (!$fields) err('Nothing to update');

        $nameStmt = $db->prepare("SELECT name FROM animals WHERE id=?");
        $nameStmt->execute([$id]);
        $aName = (string)($nameStmt->fetchColumn() ?: '');

        $params[] = $id;
        $db->prepare("UPDATE animals SET " . implode(',', $fields) . ",updated_at=NOW() WHERE id=?")->execute($params);

        // Активацию/деактивацию пишем отдельным типом события — по ней потом
        // нужно понимать, кто и когда вывел животное из активных.
        if (array_key_exists('is_active', $b)) {
            $on = (int)$b['is_active'] === 1;
            $extra = '';

            // Причина выбытия (ТЗ v3.1 §6.1). Без неё нельзя ответить,
            // сколько животных пристроено, а сколько погибло.
            if (!$on && !empty($b['deactivation_reason'])) {
                $allowed = ['Устроен','Погиб','Передан','Сбежал','Возвращён владельцу'];
                if (!in_array($b['deactivation_reason'], $allowed, true)) err('Неизвестная причина выбытия');
                $db->prepare("UPDATE animals SET deactivation_reason=?, deactivated_at=CURDATE(), deactivation_note=? WHERE id=?")
                   ->execute([$b['deactivation_reason'], $b['deactivation_note'] ?? null, $id]);
                $extra .= ' — ' . $b['deactivation_reason'];

                // «Устроен» — то же событие, что «Уехал домой» в пристройстве.
                // Проставляем статус здесь, чтобы не заставлять вносить дважды.
                if ($b['deactivation_reason'] === 'Устроен') {
                    try {
                        ensurePlacementTables($db);
                        $st = $db->prepare("SELECT id FROM placement_statuses WHERE name='Уехал домой' AND is_active=1");
                        $st->execute();
                        $sid = $st->fetchColumn();
                        if ($sid) {
                            $db->prepare("INSERT INTO animal_placement (animal_id,status_id,status_since)
                                          VALUES (?,?,CURDATE())
                                          ON DUPLICATE KEY UPDATE status_id=VALUES(status_id), status_since=CURDATE()")
                               ->execute([$id, $sid]);
                            $extra .= ', статус пристройства: Уехал домой';
                        }
                    } catch (Exception $e) { /* не критично для деактивации */ }
                }
            }
            if ($on) {
                $db->prepare("UPDATE animals SET deactivation_reason=NULL, deactivated_at=NULL, deactivation_note=NULL WHERE id=?")->execute([$id]);
            }
            if (!$on) {
                // Животного в приюте больше нет — закрываем его курсы и снимаем
                // будущие задачи. Иначе они копятся как невыполнимые: именно так
                // набралось 3950 «просроченных» задач по отсутствующим животным.
                $cnt = $db->prepare("SELECT COUNT(*) FROM procedures WHERE animal_id=? AND (course_end_date IS NULL OR course_end_date >= CURDATE())");
                $cnt->execute([$id]);
                $openCourses = (int)$cnt->fetchColumn();

                $db->prepare("UPDATE procedures SET course_end_date=CURDATE(), updated_at=NOW()
                              WHERE animal_id=? AND (course_end_date IS NULL OR course_end_date >= CURDATE())")->execute([$id]);

                $del = $db->prepare("DELETE FROM tasks WHERE animal_id=? AND is_completed=0 AND date > CURDATE()");
                $del->execute([$id]);
                $extra = " (закрыто курсов: $openCourses, снято будущих задач: " . $del->rowCount() . ")";
            }
            logAudit($db, $on ? 'animalActivated' : 'animalDeactivated',
                     ($on ? 'Животное восстановлено: ' : 'Животное деактивировано: ') . $aName . $extra, $id, $aName, 'animal');
        } else {
            $changed = implode(', ', array_map(fn($f) => trim($f, '`=?'), $fields));
            logAudit($db, 'animalUpdated', 'Изменено животное: ' . $aName . ' (' . $changed . ')', $id, $aName, 'animal');
        }
        ok(['updated' => true]);
    }

    if ($method === 'DELETE' && $id) {
        $nameStmt = $db->prepare("SELECT name FROM animals WHERE id=?");
        $nameStmt->execute([$id]);
        $aName = (string)($nameStmt->fetchColumn() ?: '');
        $db->prepare("UPDATE animals SET is_active=0, updated_at=NOW() WHERE id=?")->execute([$id]);
        logAudit($db, 'animalDeactivated', 'Животное деактивировано: ' . $aName, $id, $aName, 'animal');
        ok(['deactivated' => true]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// PROCEDURES
// ══════════════════════════════════════════════════════════════

// ── ПЕРИОДИЧНОСТЬ ─────────────────────────────────────────────
// Активна ли процедура в конкретный день. Раньше этой проверки не было
// вообще: генератор создавал задачи КАЖДЫЙ день независимо от того, выбрал
// врач «через день», «по дням недели» или пульсотерапию. Существующие
// задачи в базе сформированы корректно — их делало прежнее приложение.
function isActiveOnDate(string $periodType, DateTime $start, DateTime $day, array $b): bool {
    $offset = (int)$start->diff($day)->format('%a');   // дней от начала курса

    switch ($periodType) {
        case 'everyNDays':
            $n = max(1, (int)($b['every_n_days'] ?? 1));
            return $offset % $n === 0;

        case 'weekly':
            $days = $b['week_days'] ?? [];
            if (!is_array($days)) $days = json_decode((string)$days, true) ?: [];
            if (!$days) return false;
            // ISO-8601: 1 — понедельник … 7 — воскресенье
            return in_array((int)$day->format('N'), array_map('intval', $days), true);

        case 'monthly':
            $days = $b['month_days'] ?? [];
            if (!is_array($days)) $days = json_decode((string)$days, true) ?: [];
            if (!$days) return false;
            return in_array((int)$day->format('j'), array_map('intval', $days), true);

        case 'yearly':
            $yd = $b['yearly_date'] ?? null;
            if (!$yd) return false;
            return substr((string)$yd, 5, 5) === $day->format('m-d');

        case 'cycle':
            // Пульсотерапия: activeDays приёма, затем pauseDays паузы,
            // и так cycleCount раз.
            $cfg = $b['cycle_config'] ?? null;
            if (!is_array($cfg)) $cfg = json_decode((string)$cfg, true) ?: [];
            $active = max(1, (int)($cfg['activeDays'] ?? 0));
            $pause  = max(0, (int)($cfg['pauseDays']  ?? 0));
            $count  = max(1, (int)($cfg['cycleCount'] ?? 1));
            $len    = $active + $pause;
            if ($len <= 0) return false;
            if ($offset >= $len * $count) return false;     // все циклы пройдены
            return ($offset % $len) < $active;

        case 'daily':
        default:
            return true;
    }
}

// ── АВТОГЕНЕРАЦИЯ ЗАДАЧ ПО НАЗНАЧЕНИЮ ─────────────────────────
function generateTasksForProcedure($db, $procId, $b): int {
    $animalId = $b['animal_id'] ?? null;
    if (!$animalId) return 0;

    $periodType = $b['period_type'] ?? 'daily';
    $startDate  = $b['start_date'] ?? date('Y-m-d');
    $endDate    = $b['course_end_date'] ?? null;

    $start = new DateTime($startDate);
    $start->setTime(0, 0);

    // Горизонт: до конца курса, но не дальше 120 дней вперёд — иначе
    // бессрочный курс залил бы таблицу задачами на годы вперёд.
    $horizon = (new DateTime())->setTime(0, 0)->modify('+120 days');
    $limit   = $endDate ? new DateTime($endDate) : clone $horizon;
    $limit->setTime(0, 0);
    if ($limit > $horizon) $limit = $horizon;

    // Прошлые дни не заполняем: отмечать задним числом работу, которой не было,
    // никто не станет, а в просроченных они осядут навсегда.
    $today = (new DateTime())->setTime(0, 0);
    $cursor = ($start < $today) ? clone $today : clone $start;

    $timeSlots = $b['time_slots'] ?? ['slot_09_10'];
    if (!is_array($timeSlots)) $timeSlots = json_decode((string)$timeSlots, true) ?: ['slot_09_10'];
    if (!$timeSlots) $timeSlots = ['slot_09_10'];

    $stmt = $db->prepare("INSERT INTO tasks (id,animal_id,procedure_id,date,time_of_day,is_completed,created_at) VALUES (?,?,?,?,?,0,NOW())");
    $created = 0;
    $guard = 0;

    while ($cursor <= $limit && $guard++ < 400) {
        // Смещение считаем от НАЧАЛА курса, а не от сегодня: иначе
        // «через день» сдвинется, если назначение завели с опозданием.
        if (isActiveOnDate($periodType, $start, $cursor, $b)) {
            $dateStr = $cursor->format('Y-m-d');
            foreach ($timeSlots as $slot) {
                try {
                    $stmt->execute([bin2hex(random_bytes(16)), $animalId, $procId, $dateStr, $slot]);
                    $created++;
                } catch (Exception $e) {
                    // Дубликат отсекается UNIQUE-индексом uniq_task — это нормально.
                }
            }
        }
        $cursor->modify('+1 day');
    }
    return $created;
}

// ══════════════════════════════════════════════════════════════
// ДОСОЗДАНИЕ ЗАДАЧ ВПЕРЁД
// ══════════════════════════════════════════════════════════════
// Прежнее приложение генерировало задачи регулярно. В PHP-версии генерация
// была только в момент создания назначения — из-за чего у бессрочных курсов
// задачи заканчивались, и животные молча пропадали из обхода.
// Эта функция добирает недостающие дни до горизонта. Идемпотентна:
// повторный запуск ничего не дублирует (UNIQUE-индекс + INSERT IGNORE).
function topUpTasks(PDO $db, int $horizonDays = 30, int $maxProcedures = 1000): array {
    $horizon = (new DateTime())->setTime(0, 0)->modify("+{$horizonDays} days");
    $today   = (new DateTime())->setTime(0, 0);

    // Берём только курсы, которым действительно не хватает задач,
    // и только у активных животных — деактивированным работа не нужна.
    $stmt = $db->prepare("
        SELECT p.id, p.animal_id, p.period_type, p.start_date, p.course_end_date,
               p.every_n_days, p.week_days, p.month_days, p.yearly_date, p.cycle_config, p.time_slots,
               MAX(t.date) AS last_task
        FROM procedures p
        JOIN animals a ON p.animal_id = a.id AND a.is_active = 1
        LEFT JOIN tasks t ON t.procedure_id = p.id
        WHERE (p.course_end_date IS NULL OR p.course_end_date >= CURDATE())
        GROUP BY p.id
        HAVING last_task IS NULL OR last_task < ?
        LIMIT {$maxProcedures}");
    $stmt->execute([$horizon->format('Y-m-d')]);
    $procs = $stmt->fetchAll();

    // INSERT IGNORE вместо try/catch на каждой строке: дубликаты отсекает
    // уникальный индекс, а исключения на тысячах вставок были бы медленными.
    $ins = $db->prepare("INSERT IGNORE INTO tasks (id,animal_id,procedure_id,date,time_of_day,is_completed,created_at)
                         VALUES (?,?,?,?,?,0,NOW())");

    $created = 0; $touched = 0;
    foreach ($procs as $p) {
        $start = new DateTime($p['start_date'] ?: 'today'); $start->setTime(0, 0);

        // Начинаем с ЗАВТРА, а не с сегодня. Досоздание может сработать в любой
        // момент дня, и дописывать задачи в текущий день нельзя: люди уже
        // работают по сложившемуся списку, а новые строки сразу попали бы
        // в «просроченные» и создали ложную картину отставания.
        $tomorrow = (clone $today)->modify('+1 day');
        $from = $p['last_task'] ? (new DateTime($p['last_task']))->modify('+1 day') : clone $start;
        $from->setTime(0, 0);
        if ($from < $tomorrow) $from = clone $tomorrow;

        $to = clone $horizon;
        if ($p['course_end_date']) {
            $end = new DateTime($p['course_end_date']); $end->setTime(0, 0);
            if ($end < $to) $to = $end;
        }
        if ($from > $to) continue;

        $slots = json_decode((string)$p['time_slots'], true) ?: ['slot_09_10'];
        // Поля периодичности приходят из БД строками — приводим к тому виду,
        // который ожидает isActiveOnDate.
        $cfg = [
            'every_n_days' => $p['every_n_days'],
            'week_days'    => json_decode((string)$p['week_days'], true),
            'month_days'   => json_decode((string)$p['month_days'], true),
            'yearly_date'  => $p['yearly_date'],
            'cycle_config' => json_decode((string)$p['cycle_config'], true),
        ];

        $cursor = clone $from; $guard = 0; $any = false;
        while ($cursor <= $to && $guard++ < 400) {
            if (isActiveOnDate($p['period_type'] ?: 'daily', $start, $cursor, $cfg)) {
                $dateStr = $cursor->format('Y-m-d');
                foreach ($slots as $slot) {
                    $ins->execute([bin2hex(random_bytes(16)), $p['animal_id'], $p['id'], $dateStr, $slot]);
                    $created += $ins->rowCount();   // 0, если дубликат отсеян
                    $any = true;
                }
            }
            $cursor->modify('+1 day');
        }
        if ($any) $touched++;
    }
    return ['procedures_checked' => count($procs), 'procedures_topped_up' => $touched, 'tasks_created' => $created];
}

// Точка запуска: и для планировщика, и для приложения.
function maintenanceHandler(): void {
    $db   = db();
    $days = isset($_GET['days']) ? min(120, max(1, (int)$_GET['days'])) : 30;

    $t0 = microtime(true);
    $res = topUpTasks($db, $days);
    $res['seconds'] = round(microtime(true) - $t0, 2);
    $res['horizon_days'] = $days;

    if ($res['tasks_created'] > 0) {
        logAudit($db, 'other',
                 "Досоздание задач: добавлено {$res['tasks_created']} по {$res['procedures_topped_up']} назначениям",
                 null, null, 'system');
    }
    ok($res);
}

function proceduresHandler(string $method, ?string $id): void {
    $db = db();

    if ($method === 'GET') {
        if ($id) {
            $stmt = $db->prepare("SELECT p.*, a.name as animal_name, a.route_id, r.name as route_name FROM procedures p JOIN animals a ON p.animal_id=a.id LEFT JOIN routes r ON a.route_id=r.id WHERE p.id=?");
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            if (!$row) err('Procedure not found', 404);
            $row['time_slots'] = decodeJson($row['time_slots']);
            $row['week_days']  = decodeJson($row['week_days']);
            $row['month_days'] = decodeJson($row['month_days']);
            $row['cycle_config'] = decodeJson($row['cycle_config']);
            ok($row);
        }

        $where = [];
        $params = [];

        if (!empty($_GET['animal_id'])) {
            $where[] = 'p.animal_id=?';
            $params[] = $_GET['animal_id'];
        }
        if (!empty($_GET['route_id'])) {
            $where[] = 'a.route_id=?';
            $params[] = $_GET['route_id'];
        }
        if (!empty($_GET['group'])) {
            $where[] = 'p.`group`=?';
            $params[] = $_GET['group'];
        }
        if (!empty($_GET['status'])) {
            if ($_GET['status'] === 'active') {
                $where[] = '(p.course_end_date IS NULL OR p.course_end_date >= CURDATE())';
            } elseif ($_GET['status'] === 'ended') {
                $where[] = 'p.course_end_date < CURDATE()';
            } elseif ($_GET['status'] === 'upcoming') {
                $where[] = 'p.start_date > CURDATE()';
            }
        }
        if (!empty($_GET['ending_today'])) {
            $where[] = 'DATE(p.course_end_date) BETWEEN DATE_SUB(CURDATE(), INTERVAL 1 DAY) AND DATE_ADD(CURDATE(), INTERVAL 0 DAY)';
        }
        if (!empty($_GET['ending_days'])) {
            $days = (int)$_GET['ending_days'];
            $where[] = "DATE(p.course_end_date) BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL ? DAY)";
            $params[] = $days;
        }

        // needs_review — бессрочные курсы, по которым давно нет отметок.
        // Именно они не попадали в списки из-за обрыва генерации задач:
        // врач их не видел и не мог завершить, даже если лечение закончилось.
        if (!empty($_GET['needs_review'])) {
            $rd = isset($_GET['review_days']) ? max(1, (int)$_GET['review_days']) : 14;
            $where[] = 'p.course_end_date IS NULL';
            $where[] = 'a.is_active = 1';
            $where[] = "NOT EXISTS (SELECT 1 FROM tasks t WHERE t.procedure_id = p.id
                                    AND t.is_completed = 1
                                    AND t.date >= DATE_SUB(CURDATE(), INTERVAL ? DAY))";
            $params[] = $rd;
        }

        $sql = "SELECT p.*, a.name as animal_name, a.route_id, a.room, a.cage_number, r.name as route_name,
                       (SELECT MAX(t.date) FROM tasks t WHERE t.procedure_id=p.id AND t.is_completed=1) AS last_done
                FROM procedures p JOIN animals a ON p.animal_id=a.id LEFT JOIN routes r ON a.route_id=r.id";
        if ($where) $sql .= ' WHERE ' . implode(' AND ', $where);
        $sql .= ' ORDER BY p.medication_name';

        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        foreach ($rows as &$row) {
            $row['time_slots']   = decodeJson($row['time_slots']);
            $row['week_days']    = decodeJson($row['week_days']);
            $row['month_days']   = decodeJson($row['month_days']);
            $row['cycle_config'] = decodeJson($row['cycle_config']);
        }
        ok($rows);
    }

    if ($method === 'POST') {
        $b = body();
        $id = $b['id'] ?? bin2hex(random_bytes(16));
        $stmt = $db->prepare("INSERT INTO procedures (id,animal_id,medication_name,dosage,`group`,administration_route,doctor_name,period_type,frequency,duration_days,start_date,course_end_date,course_end_type,total_repetitions,every_n_days,week_days,month_days,yearly_date,cycle_config,time_slots,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        $stmt->execute([
            $id, $b['animal_id'], $b['medication_name'], $b['dosage']??null,
            $b['group']??null, $b['administration_route']??null, $b['doctor_name']??null,
            $b['period_type']??'daily', $b['frequency']??1, $b['duration_days']??null,
            $b['start_date']??null, $b['course_end_date']??null, $b['course_end_type']??null,
            $b['total_repetitions']??null, $b['every_n_days']??null,
            isset($b['week_days']) ? json_encode($b['week_days']) : null,
            isset($b['month_days']) ? json_encode($b['month_days']) : null,
            $b['yearly_date']??null,
            isset($b['cycle_config']) ? json_encode($b['cycle_config']) : null,
            isset($b['time_slots']) ? json_encode($b['time_slots']) : null,
            $b['notes']??null,
        ]);
        $created = generateTasksForProcedure($db, $id, $b);
        logAudit($db, 'procedureCreated',
                 'Создано назначение «' . ($b['medication_name'] ?? '') . '» (задач сформировано: ' . $created . ')',
                 $id, $b['medication_name'] ?? '', 'procedure');
        ok(['id' => $id, 'tasks_generated' => $created], 201);
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        $action = $b['action'] ?? 'update';
        $actor  = currentUser();   // кто выполняет действие — для журнала

        // ── ЗАВЕРШИТЬ КУРС ────────────────────────────────────────
        if ($action === 'complete') {
            $db->prepare("UPDATE procedures SET course_end_date=DATE_SUB(CURDATE(), INTERVAL 1 DAY), updated_at=NOW() WHERE id=?")->execute([$id]);
            // Log to audit
            $proc = $db->prepare("SELECT p.medication_name, a.name as animal_name FROM procedures p JOIN animals a ON p.animal_id=a.id WHERE p.id=?");
            $proc->execute([$id]);
            $row = $proc->fetch();
            $logId = bin2hex(random_bytes(16));
            $db->prepare("INSERT INTO audit_logs (id,action_type,description,target_id,target_name,target_type,user_id,user_name,timestamp) VALUES (?,?,?,?,?,?,?,?,NOW())")
               ->execute([$logId, 'courseCompleted', 'Курс завершён: ' . ($row['animal_name']??'') . ' - ' . ($row['medication_name']??''), $id, ($row['animal_name']??'') . ' - ' . ($row['medication_name']??''), 'procedure', $actor['id']??null, $actor['name']??null]);
            ok(['completed' => true]);
        }

        // ── ПРОДЛИТЬ КУРС ─────────────────────────────────────────
        if ($action === 'extend') {
            $fields = []; $params = [];
            // New end date: either specific date or +N days from today
            if (!empty($b['new_end_date'])) {
                $fields[] = 'course_end_date=?'; $params[] = $b['new_end_date'];
            } elseif (!empty($b['extend_days'])) {
                $fields[] = 'course_end_date=DATE_ADD(CURDATE(), INTERVAL ? DAY)'; $params[] = (int)$b['extend_days'];
                $fields[] = 'duration_days=?'; $params[] = (int)$b['extend_days'];
            }
            if (!empty($b['dosage']))     { $fields[] = 'dosage=?';     $params[] = $b['dosage']; }
            if (!empty($b['notes']))      { $fields[] = 'notes=?';      $params[] = $b['notes']; }
            if (!empty($b['frequency'])) { $fields[] = 'frequency=?';  $params[] = (int)$b['frequency']; }
            if (!$fields) err('Не указаны параметры продления');
            $params[] = $id;
            $db->prepare("UPDATE procedures SET " . implode(',', $fields) . ", updated_at=NOW() WHERE id=?")->execute($params);
            // Log
            $proc = $db->prepare("SELECT p.medication_name, a.name as animal_name FROM procedures p JOIN animals a ON p.animal_id=a.id WHERE p.id=?");
            $proc->execute([$id]);
            $row = $proc->fetch();
            $logId = bin2hex(random_bytes(16));
            $endInfo = !empty($b['new_end_date']) ? 'до ' . $b['new_end_date'] : 'на ' . ($b['extend_days']??'?') . ' дней';
            $db->prepare("INSERT INTO audit_logs (id,action_type,description,target_id,target_name,target_type,user_id,user_name,timestamp) VALUES (?,?,?,?,?,?,?,?,NOW())")
               ->execute([$logId, 'courseExtended', 'Курс продлён ' . $endInfo . ': ' . ($row['animal_name']??'') . ' - ' . ($row['medication_name']??''), $id, ($row['animal_name']??''), 'procedure', $actor['id']??null, $actor['name']??null]);
            ok(['extended' => true]);
        }

        // ── РЕДАКТИРОВАТЬ ─────────────────────────────────────────
        $fields = []; $params = [];
        $simple = ['medication_name','dosage','group','administration_route','doctor_name','period_type','frequency','duration_days','start_date','course_end_date','course_end_type','total_repetitions','every_n_days','yearly_date','notes'];
        foreach ($simple as $f) {
            if (array_key_exists($f, $b)) { $fields[] = "`$f`=?"; $params[] = $b[$f]; }
        }
        foreach (['time_slots','week_days','month_days','cycle_config'] as $f) {
            if (array_key_exists($f, $b)) { $fields[] = "`$f`=?"; $params[] = json_encode($b[$f]); }
        }
        if (!$fields) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE procedures SET " . implode(',', $fields) . ",updated_at=NOW() WHERE id=?")->execute($params);
        ok(['updated' => true]);
    }

    if ($method === 'DELETE' && $id) {
        $actor = currentUser();
        $info  = $db->prepare("SELECT p.medication_name, a.name AS animal_name FROM procedures p JOIN animals a ON p.animal_id=a.id WHERE p.id=?");
        $info->execute([$id]);
        $row = $info->fetch() ?: [];

        $db->beginTransaction();
        try {
            // Удаляем только НЕвыполненные задачи — это будущая работа, её больше не нужно.
            // Выполненные оставляем: это запись о реально введённом препарате,
            // то есть медицинская история животного, и стирать её нельзя.
            $del = $db->prepare("DELETE FROM tasks WHERE procedure_id=? AND is_completed=0");
            $del->execute([$id]);
            $removed = $del->rowCount();

            $kept = $db->prepare("SELECT COUNT(*) FROM tasks WHERE procedure_id=? AND is_completed=1");
            $kept->execute([$id]);
            $keptCount = (int)$kept->fetchColumn();

            $db->prepare("DELETE FROM procedures WHERE id=?")->execute([$id]);

            $label = trim(($row['animal_name'] ?? '') . ' — ' . ($row['medication_name'] ?? ''));
            $db->prepare("INSERT INTO audit_logs (id,action_type,description,target_id,target_name,target_type,user_id,user_name,timestamp) VALUES (?,?,?,?,?,?,?,?,NOW())")
               ->execute([bin2hex(random_bytes(16)), 'procedureDeleted',
                          "Удалено назначение: $label (снято невыполненных задач: $removed, сохранено выполненных: $keptCount)",
                          $id, $label, 'procedure', $actor['id'] ?? null, $actor['name'] ?? null]);
            $db->commit();
        } catch (Exception $e) {
            $db->rollBack();
            throw $e;
        }
        ok(['deleted' => true, 'tasks_removed' => $removed, 'completed_tasks_kept' => $keptCount]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// TASKS
// ══════════════════════════════════════════════════════════════
function tasksHandler(string $method, ?string $id): void {
    $db = db();

    if ($method === 'GET') {
        if ($id) {
            $stmt = $db->prepare("SELECT t.*,p.medication_name,p.dosage,p.`group`,p.time_slots,a.name as animal_name,a.route_id,a.room,a.cage_number,r.name as route_name FROM tasks t JOIN procedures p ON t.procedure_id=p.id JOIN animals a ON t.animal_id=a.id LEFT JOIN routes r ON a.route_id=r.id WHERE t.id=?");
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            if (!$row) err('Task not found', 404);
            ok($row);
        }

        $where = [];
        $params = [];

        // Задачи деактивированных животных не показываем: животного в приюте
        // уже нет (пристроено, переведено, умерло), выполнить их невозможно.
        // Они же составляли больше половины «просроченных» — 3950 из 7655.
        if (empty($_GET['include_inactive'])) $where[] = 'a.is_active = 1';

        // overdue=1 — невыполненные задачи за прошедшие дни. Их тысячи,
        // поэтому обязателен предел и сортировка от свежих к старым.
        $overdue = !empty($_GET['overdue']);
        if ($overdue) {
            $where[] = 't.date < CURDATE()';
            $where[] = 't.is_completed=0';
            $days = isset($_GET['days']) ? max(1, (int)$_GET['days']) : 14;
            $where[] = 't.date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)';
            $params[] = $days;
        } else {
            $date = $_GET['date'] ?? date('Y-m-d');
            $where[] = 't.date=?';
            $params[] = $date;
        }

        if (!empty($_GET['animal_id'])) { $where[] = 't.animal_id=?'; $params[] = $_GET['animal_id']; }
        if (!empty($_GET['route_id'])) { $where[] = 'a.route_id=?'; $params[] = $_GET['route_id']; }
        if (!empty($_GET['group'])) { $where[] = 'p.`group`=?'; $params[] = $_GET['group']; }
        if (isset($_GET['is_completed'])) {
            $where[] = 't.is_completed=?';
            $params[] = $_GET['is_completed'] === 'true' ? 1 : 0;
        }
        if (!empty($_GET['time_of_day'])) { $where[] = 't.time_of_day=?'; $params[] = $_GET['time_of_day']; }
        if (!empty($_GET['search'])) {
            $where[] = '(a.name LIKE ? OR p.medication_name LIKE ?)';
            $params[] = '%' . $_GET['search'] . '%';
            $params[] = '%' . $_GET['search'] . '%';
        }

        $sql = "SELECT t.*, p.medication_name, p.dosage, p.`group`, p.notes as proc_notes, p.administration_route, p.start_date, p.course_end_date, a.name as animal_name, a.route_id, a.room, a.cage_number, a.gender, r.name as route_name, u.name as completed_by_name FROM tasks t JOIN procedures p ON t.procedure_id=p.id JOIN animals a ON t.animal_id=a.id LEFT JOIN routes r ON a.route_id=r.id LEFT JOIN users u ON t.completed_by=u.id";
        if ($where) $sql .= ' WHERE ' . implode(' AND ', $where);
        $sql .= $overdue ? ' ORDER BY t.date DESC, t.time_of_day' : ' ORDER BY t.time_of_day, a.name';

        // Предел только для просроченных: список задач на день и так небольшой,
        // а обрезать его молча — значит скрыть от исполнителя часть работы.
        if ($overdue) {
            $limit = isset($_GET['limit']) ? min(1000, max(1, (int)$_GET['limit'])) : 300;
            $sql .= ' LIMIT ' . $limit;
        }

        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        ok($stmt->fetchAll());
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        if (!isset($b['is_completed'])) err('Nothing to update');

        $completed = filter_var($b['is_completed'], FILTER_VALIDATE_BOOLEAN);
        $actor     = currentUser();
        // Исполнителя берём из токена, а не из тела запроса: иначе выполнение
        // можно записать на чужое имя. Поле из тела — только запасной вариант.
        $actorId   = $actor['id'] ?? ($b['completed_by'] ?? null);

        if ($completed) {
            // notes трогаем только если они реально переданы — раньше
            // безусловное notes=? затирало заметку при повторной отметке.
            if (array_key_exists('notes', $b)) {
                $db->prepare("UPDATE tasks SET is_completed=1, completed_by=?, completed_at=NOW(), notes=? WHERE id=?")
                   ->execute([$actorId, $b['notes'], $id]);
            } else {
                $db->prepare("UPDATE tasks SET is_completed=1, completed_by=?, completed_at=NOW() WHERE id=?")
                   ->execute([$actorId, $id]);
            }
        } else {
            $db->prepare("UPDATE tasks SET is_completed=0, completed_by=NULL, completed_at=NULL WHERE id=?")->execute([$id]);
        }

        // Журнал: кто и что отметил. Не должен ломать саму отметку.
        try {
            $info = $db->prepare("SELECT p.medication_name, a.name AS animal_name FROM tasks t JOIN procedures p ON t.procedure_id=p.id JOIN animals a ON t.animal_id=a.id WHERE t.id=?");
            $info->execute([$id]);
            $row   = $info->fetch() ?: [];
            $label = trim(($row['animal_name'] ?? '') . ' — ' . ($row['medication_name'] ?? ''));
            $db->prepare("INSERT INTO audit_logs (id,action_type,description,target_id,target_name,target_type,user_id,user_name,timestamp) VALUES (?,?,?,?,?,?,?,?,NOW())")
               ->execute([
                   bin2hex(random_bytes(16)),
                   $completed ? 'taskCompleted' : 'taskUncompleted',
                   ($completed ? 'Задача выполнена: ' : 'Отметка снята: ') . $label,
                   $id, $label, 'task',
                   $actor['id'] ?? null, $actor['name'] ?? null,
               ]);
        } catch (Exception $e) { /* журнал не критичен для выполнения задачи */ }

        ok(['updated' => true, 'is_completed' => $completed ? 1 : 0]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// USERS
// ══════════════════════════════════════════════════════════════
function usersHandler(string $method, ?string $id): void {
    $db = db();

    if ($method === 'GET') {
        if ($id) {
            $stmt = $db->prepare("SELECT id,name,email,username,role,is_active,is_first_login,created_at FROM users WHERE id=?");
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            if (!$row) err('User not found', 404);
            ok($row);
        }
        $role = $_GET['role'] ?? null;
        if ($role) {
            $stmt = $db->prepare("SELECT id,name,email,username,role,is_active FROM users WHERE role=? AND is_active=1 ORDER BY name");
            $stmt->execute([$role]);
        } else {
            $stmt = $db->query("SELECT id,name,email,username,role,is_active FROM users WHERE is_active=1 ORDER BY name");
        }
        ok($stmt->fetchAll());
    }

    if ($method === 'POST') {
        $b = body();
        if (empty($b['name'])) err('Не указано имя пользователя');
        $role = $b['role'] ?? 'executor';
        if (!in_array($role, ['techAdmin','doctor','shelterAdmin','executor'], true)) err('Неизвестная роль: ' . $role);

        $id   = bin2hex(random_bytes(16));
        $hash = hashPassword($b['password'] ?? 'changeme123');

        // Логин: берём заданный явно, иначе строим из имени транслитерацией.
        $username = trim((string)($b['username'] ?? ''));
        if ($username === '') $username = makeUsername($b['name']);
        $username = uniqueUsername($db, $username);

        $stmt = $db->prepare("INSERT INTO users (id,name,email,username,role,password_hash,is_first_login) VALUES (?,?,?,?,?,?,0)");
        $stmt->execute([$id, $b['name'], $b['email']??null, $username, $role, $hash]);
        // Задачи здесь НЕ генерируются — пользователь не порождает назначений.
        logAudit($db, 'userCreated', 'Добавлен сотрудник: ' . $b['name'] . ' (' . $role . '), логин ' . $username, $id, $b['name'], 'user');
        ok(['id' => $id, 'username' => $username], 201);
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        $fields = []; $params = [];

        // Роль проверяем по списку: опечатка в ней тихо лишила бы человека
        // доступа или, наоборот, выдала лишний.
        if (array_key_exists('role', $b) && !in_array($b['role'], ['techAdmin','doctor','shelterAdmin','executor'], true)) {
            err('Неизвестная роль: ' . $b['role']);
        }

        // Учётку технического администратора может править только он сам или
        // другой техадмин. У врачей полный доступ ко всей работе приюта, но
        // возможность сменить пароль администратору означала бы, что взлом
        // любой из семи учёток даёт контроль над системой целиком.
        $me = currentUser();
        $tgt = $db->prepare("SELECT role FROM users WHERE id=?");
        $tgt->execute([$id]);
        $targetRole = $tgt->fetchColumn();
        if ($targetRole === 'techAdmin' && ($me['role'] ?? '') !== 'techAdmin') {
            err('Учётную запись технического администратора может изменить только он сам.');
        }
        // Повысить кого-то до техадмина тоже может только техадмин — иначе
        // ограничение выше обходится в два шага.
        if (($b['role'] ?? '') === 'techAdmin' && ($me['role'] ?? '') !== 'techAdmin') {
            err('Назначить технического администратора может только действующий техадмин.');
        }

        if ($me && $me['id'] === $id) {
            if (array_key_exists('role', $b) && $b['role'] !== $me['role']) {
                err('Нельзя менять роль самому себе. Попросите это сделать другого администратора.');
            }
            if (array_key_exists('is_active', $b) && (int)$b['is_active'] === 0) {
                err('Нельзя отключить собственную учётную запись.');
            }
        }
        // Последнего техадмина тоже не отпускаем — иначе управлять
        // пользователями станет некому.
        if (array_key_exists('role', $b) && $b['role'] !== 'techAdmin') {
            $cur = $db->prepare("SELECT role FROM users WHERE id=?");
            $cur->execute([$id]);
            if ($cur->fetchColumn() === 'techAdmin') {
                $cnt = (int)$db->query("SELECT COUNT(*) FROM users WHERE role='techAdmin' AND is_active=1")->fetchColumn();
                if ($cnt <= 1) err('Это единственный технический администратор — сначала назначьте другого.');
            }
        }

        // Смена логина — только на свободный, иначе вход станет неоднозначным.
        if (array_key_exists('username', $b) && $b['username'] !== '') {
            $chk = $db->prepare("SELECT COUNT(*) FROM users WHERE username=? AND id<>?");
            $chk->execute([$b['username'], $id]);
            if ((int)$chk->fetchColumn() > 0) err('Логин «' . $b['username'] . '» уже занят');
            $fields[] = '`username`=?'; $params[] = $b['username'];
        }

        foreach (['name','email','role','is_active'] as $f) {
            if (array_key_exists($f, $b)) { $fields[] = "`$f`=?"; $params[] = $b[$f]; }
        }
        $passwordChanged = isset($b['password']) && $b['password'] !== '';
        if ($passwordChanged) {
            $fields[] = 'password_hash=?';
            $params[] = hashPassword($b['password']);
            if (isset($b['is_first_login'])) { $fields[] = 'is_first_login=?'; $params[] = (int)$b['is_first_login']; }
        }
        if (!$fields) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE users SET " . implode(',', $fields) . " WHERE id=?")->execute($params);

        // Смена пароля обрывает все сессии этого пользователя. Иначе смена
        // пароля после утечки была бы бессмысленной: старый токен продолжал бы
        // работать, потому что он от пароля не зависит.
        if ($passwordChanged) {
            revokeTokens($db, $id);
            $n = $db->prepare("SELECT name FROM users WHERE id=?"); $n->execute([$id]);
            logAudit($db, 'userUpdated', 'Смена пароля: ' . (string)($n->fetchColumn() ?: ''), $id, null, 'user');
        }
        ok(['updated' => true, 'sessions_revoked' => $passwordChanged]);
    }

    if ($method === 'DELETE' && $id) {
        // Soft delete — deactivate
        $db->prepare("UPDATE users SET is_active=0 WHERE id=?")->execute([$id]);
        ok(['deleted' => true]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════
function authHandler(string $method): void {
    if ($method !== 'POST') err('Method not allowed', 405);
    $b = body();
    $login = $b['username'] ?? $b['email'] ?? '';
    $pass  = $b['password'] ?? '';
    if (!$login || !$pass) err('Введите логин и пароль');

    $db = db();
    ensureTokenSecretColumn($db);

    // Пароль больше НЕ участвует в SQL-условии: хеши теперь разного формата,
    // сравнивать их надо в PHP. Ищем по логину, потом проверяем пароль.
    $stmt = $db->prepare("SELECT id,name,email,username,role,is_active,is_first_login,password_hash,token_secret
                          FROM users WHERE (username=? OR email=?) AND is_active=1 LIMIT 1");
    $stmt->execute([$login, $login]);
    $user = $stmt->fetch();

    if (!$user || !verifyPassword($pass, (string)$user['password_hash'])) {
        err('Неверный логин или пароль', 401);
    }

    // Незаметно переводим пароль на современный формат при первом же входе.
    if (isLegacyHash((string)$user['password_hash'])) {
        $db->prepare("UPDATE users SET password_hash=? WHERE id=?")->execute([hashPassword($pass), $user['id']]);
    }

    if ($user['is_first_login']) {
        $db->prepare("UPDATE users SET is_first_login=0 WHERE id=?")->execute([$user['id']]);
    }
    // Колонки last_login может не быть — она из старой схемы; отсутствие
    // не должно мешать входу.
    try { $db->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$user['id']]); }
    catch (Exception $e) { /* нет колонки — не критично */ }

    $token = issueToken($db, $user);
    unset($user['password_hash'], $user['token_secret']);
    logAudit($db, 'userLogin', 'Вход в систему: ' . $user['name'], $user['id'], $user['name'], 'user');

    ok(['user' => $user, 'token' => $token]);
}

// ══════════════════════════════════════════════════════════════
// STATS (главная страница)
// ══════════════════════════════════════════════════════════════
function statsHandler(): void {
    $db = db();
    $today = date('Y-m-d');

    $stats = [];

    // Животные
    $stats['animals_active']   = (int)$db->query("SELECT COUNT(*) FROM animals WHERE is_active=1")->fetchColumn();
    $stats['animals_inactive'] = (int)$db->query("SELECT COUNT(*) FROM animals WHERE is_active=0")->fetchColumn();
    $stats['animals_critical'] = (int)$db->query("SELECT COUNT(*) FROM animals WHERE is_active=1 AND status='critical'")->fetchColumn();
    $stats['animals_stable']   = (int)$db->query("SELECT COUNT(*) FROM animals WHERE is_active=1 AND status='stable'")->fetchColumn();

    $stats['animals_moderate'] = (int)$db->query("SELECT COUNT(*) FROM animals WHERE is_active=1 AND status='moderate'")->fetchColumn();

    // Разбивка по видам — нужна для вкладки аналитики «Животные».
    $stats['by_species'] = $db->query("SELECT species, COUNT(*) AS cnt FROM animals WHERE is_active=1 GROUP BY species ORDER BY cnt DESC")->fetchAll();
    $stats['by_gender']  = $db->query("SELECT gender, COUNT(*) AS cnt FROM animals WHERE is_active=1 GROUP BY gender")->fetchAll();

    // Маршруты
    $stats['routes_count'] = (int)$db->query("SELECT COUNT(*) FROM routes")->fetchColumn();

    // Назначения
    $stats['procedures_active'] = (int)$db->query("SELECT COUNT(*) FROM procedures WHERE course_end_date IS NULL OR course_end_date >= CURDATE()")->fetchColumn();
    $stmt = $db->prepare("SELECT COUNT(*) FROM procedures WHERE DATE(course_end_date)=?");
    $stmt->execute([$today]);
    $stats['ending_today'] = (int)$stmt->fetchColumn();

    $stmt = $db->prepare("SELECT COUNT(*) FROM procedures WHERE course_end_date BETWEEN ? AND DATE_ADD(?,INTERVAL 3 DAY)");
    $stmt->execute([$today, $today]);
    $stats['ending_3days'] = (int)$stmt->fetchColumn();

    // Задачи сегодня. Считаем только по активным животным — так же, как их
    // показывает список задач, иначе сводка и экран расходятся.
    $stmt = $db->prepare("SELECT COUNT(*) FROM tasks t JOIN animals a ON t.animal_id=a.id WHERE t.date=? AND a.is_active=1");
    $stmt->execute([$today]);
    $stats['tasks_today'] = (int)$stmt->fetchColumn();

    $stmt = $db->prepare("SELECT COUNT(*) FROM tasks t JOIN animals a ON t.animal_id=a.id WHERE t.date=? AND t.is_completed=1 AND a.is_active=1");
    $stmt->execute([$today]);
    $stats['tasks_done'] = (int)$stmt->fetchColumn();

    $stats['tasks_pending']  = $stats['tasks_today'] - $stats['tasks_done'];
    $stats['completion_pct'] = $stats['tasks_today'] > 0
        ? round($stats['tasks_done'] / $stats['tasks_today'] * 100, 1)
        : 0;

    // Задачи невыполненные (прошлые дни)
    $stmt = $db->prepare("SELECT COUNT(*) FROM tasks t JOIN animals a ON t.animal_id=a.id WHERE t.date < ? AND t.is_completed=0 AND a.is_active=1");
    $stmt->execute([$today]);
    $stats['tasks_overdue'] = (int)$stmt->fetchColumn();

    // По маршрутам
    $routeStats = $db->query("
        SELECT r.id, r.name,
            COUNT(DISTINCT a.id) as animal_count,
            COUNT(DISTINCT CASE WHEN p.course_end_date IS NULL OR p.course_end_date >= CURDATE() THEN p.id END) as procedure_count
        FROM routes r
        LEFT JOIN animals a ON a.route_id=r.id AND a.is_active=1
        LEFT JOIN procedures p ON p.animal_id=a.id
        GROUP BY r.id, r.name ORDER BY r.name
    ")->fetchAll();
    $stats['by_route'] = $routeStats;

    // По группам (сегодня)
    $stmt = $db->prepare("
        SELECT p.`group`, COUNT(*) as total, SUM(t.is_completed) as done
        FROM tasks t
        JOIN procedures p ON t.procedure_id=p.id
        WHERE t.date=?
        GROUP BY p.`group`
        ORDER BY total DESC
    ");
    $stmt->execute([$today]);
    $groupStats = $stmt->fetchAll();
    foreach ($groupStats as &$g) {
        $g['pct'] = $g['total'] > 0 ? round($g['done'] / $g['total'] * 100) : 0;
    }
    $stats['by_group'] = $groupStats;

    ok($stats);
}

// ══════════════════════════════════════════════════════════════
// ANALYTICS
// ══════════════════════════════════════════════════════════════
function analyticsHandler(): void {
    $db   = db();
    $days = isset($_GET['days']) ? (int)$_GET['days'] : 7;
    $from = $_GET['from'] ?? date('Y-m-d', strtotime("-{$days} days"));
    $to   = $_GET['to']   ?? date('Y-m-d');

    $result = [];

    // By day
    $stmt = $db->prepare("
        SELECT date, COUNT(*) as total,
               SUM(CASE WHEN is_completed=1 THEN 1 ELSE 0 END) as completed
        FROM tasks WHERE date BETWEEN ? AND ?
        GROUP BY date ORDER BY date
    ");
    $stmt->execute([$from, $to]);
    $result['by_day'] = $stmt->fetchAll();

    // By group
    $stmt = $db->prepare("
        SELECT p.`group`, COUNT(t.id) as count
        FROM tasks t JOIN procedures p ON t.procedure_id=p.id
        WHERE t.date BETWEEN ? AND ? AND t.is_completed=1
        GROUP BY p.`group` ORDER BY count DESC
    ");
    $stmt->execute([$from, $to]);
    $result['by_group'] = $stmt->fetchAll();

    // By route
    $stmt = $db->prepare("
        SELECT r.name, COUNT(t.id) as count
        FROM tasks t
        JOIN animals a ON t.animal_id=a.id
        JOIN routes r ON a.route_id=r.id
        WHERE t.date BETWEEN ? AND ? AND t.is_completed=1
        GROUP BY r.id, r.name ORDER BY count DESC
    ");
    $stmt->execute([$from, $to]);
    $result['by_route'] = $stmt->fetchAll();

    // Top executors
    $stmt = $db->prepare("
        SELECT u.name, COUNT(*) as tasks_done
        FROM tasks t JOIN users u ON t.completed_by=u.id
        WHERE t.date BETWEEN ? AND ? AND t.is_completed=1
        GROUP BY u.id, u.name ORDER BY tasks_done DESC LIMIT 10
    ");
    $stmt->execute([$from, $to]);
    $result['top_executors'] = $stmt->fetchAll();

    // Summary
    $stmt = $db->prepare("SELECT COUNT(*) as total, SUM(is_completed) as completed FROM tasks WHERE date BETWEEN ? AND ?");
    $stmt->execute([$from, $to]);
    $result['summary'] = $stmt->fetch();

    ok($result);
}


// ══════════════════════════════════════════════════════════════
// ИСТОРИЯ ВЫДАЧИ: кто, когда, кому и что дал
// ══════════════════════════════════════════════════════════════
// Источник — таблица tasks, а не audit_logs: там структурированные поля
// (животное, препарат, доза, путь введения), а в журнале только текст.
// Плюс она покрывает всю историю с января, включая период до того, как
// в журнал начали писать автора.
function historyHandler(): void {
    $db = db();
    $where  = ['t.is_completed=1', 't.completed_at IS NOT NULL'];
    $params = [];

    $from = $_GET['from'] ?? date('Y-m-d', strtotime('-7 days'));
    $to   = $_GET['to']   ?? date('Y-m-d');
    $where[] = 't.date BETWEEN ? AND ?';
    $params[] = $from; $params[] = $to;

    if (!empty($_GET['animal_id']))   { $where[] = 't.animal_id=?';   $params[] = $_GET['animal_id']; }
    if (!empty($_GET['user_id']))     { $where[] = 't.completed_by=?'; $params[] = $_GET['user_id']; }
    if (!empty($_GET['route_id']))    { $where[] = 'a.route_id=?';    $params[] = $_GET['route_id']; }
    if (!empty($_GET['group']))       { $where[] = 'p.`group`=?';     $params[] = $_GET['group']; }
    if (!empty($_GET['search'])) {
        $where[] = '(a.name LIKE ? OR p.medication_name LIKE ?)';
        $params[] = '%' . $_GET['search'] . '%';
        $params[] = '%' . $_GET['search'] . '%';
    }

    $limit = isset($_GET['limit']) ? min(1000, max(1, (int)$_GET['limit'])) : 200;

    $sql = "SELECT t.id, t.date, t.time_of_day, t.completed_at, t.notes,
                   a.id AS animal_id, a.name AS animal_name, a.room, r.name AS route_name,
                   p.medication_name, p.dosage, p.administration_route, p.`group`,
                   u.id AS user_id, u.name AS user_name
            FROM tasks t
            JOIN procedures p ON t.procedure_id=p.id
            JOIN animals a    ON t.animal_id=a.id
            LEFT JOIN routes r ON a.route_id=r.id
            LEFT JOIN users u  ON t.completed_by=u.id
            WHERE " . implode(' AND ', $where) . "
            ORDER BY t.completed_at DESC
            LIMIT $limit";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    // Общее число — чтобы честно показать, сколько осталось за пределом выборки.
    $cntSql = "SELECT COUNT(*) FROM tasks t JOIN procedures p ON t.procedure_id=p.id
               JOIN animals a ON t.animal_id=a.id WHERE " . implode(' AND ', $where);
    $cnt = $db->prepare($cntSql);
    $cnt->execute($params);

    ok(['items' => $rows, 'total' => (int)$cnt->fetchColumn(), 'limit' => $limit, 'from' => $from, 'to' => $to]);
}

// ══════════════════════════════════════════════════════════════
// ЖУРНАЛ ИЗМЕНЕНИЙ (audit_logs)
// ══════════════════════════════════════════════════════════════
function auditHandler(): void {
    $db = db();
    $where  = [];
    $params = [];

    $from = $_GET['from'] ?? date('Y-m-d', strtotime('-7 days'));
    $to   = $_GET['to']   ?? date('Y-m-d');
    $where[] = 'DATE(timestamp) BETWEEN ? AND ?';
    $params[] = $from; $params[] = $to;

    if (!empty($_GET['action'])) { $where[] = 'action_type=?'; $params[] = $_GET['action']; }
    if (!empty($_GET['user_id'])) { $where[] = 'user_id=?';    $params[] = $_GET['user_id']; }
    if (!empty($_GET['search'])) {
        $where[] = '(description LIKE ? OR target_name LIKE ?)';
        $params[] = '%' . $_GET['search'] . '%';
        $params[] = '%' . $_GET['search'] . '%';
    }
    // Отметки задач по умолчанию скрыты: их 30 тысяч, они забивают журнал,
    // и для них есть отдельная история выдачи.
    if (empty($_GET['include_tasks'])) {
        $where[] = "action_type NOT IN ('taskCompleted','taskUncompleted')";
    }

    $limit = isset($_GET['limit']) ? min(1000, max(1, (int)$_GET['limit'])) : 200;

    $stmt = $db->prepare("SELECT id, timestamp, action_type, description, target_name, target_type, user_name
                          FROM audit_logs WHERE " . implode(' AND ', $where) . "
                          ORDER BY timestamp DESC LIMIT $limit");
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    $cnt = $db->prepare("SELECT COUNT(*) FROM audit_logs WHERE " . implode(' AND ', $where));
    $cnt->execute($params);

    ok(['items' => $rows, 'total' => (int)$cnt->fetchColumn(), 'limit' => $limit, 'from' => $from, 'to' => $to]);
}

// ══════════════════════════════════════════════════════════════
// КТО СЕГОДНЯ ГДЕ РАБОТАЕТ
// ══════════════════════════════════════════════════════════════
function staffHandler(): void {
    $db   = db();
    $date = $_GET['date'] ?? date('Y-m-d');

    // Кто сколько сделал и на каких маршрутах — основа ответа «кто где».
    $stmt = $db->prepare("
        SELECT u.id, u.name, u.role, r.name AS route_name,
               COUNT(*) AS done,
               MIN(t.completed_at) AS first_at,
               MAX(t.completed_at) AS last_at
        FROM tasks t
        JOIN users u ON t.completed_by=u.id
        JOIN animals a ON t.animal_id=a.id
        LEFT JOIN routes r ON a.route_id=r.id
        WHERE t.date=? AND t.is_completed=1
        GROUP BY u.id, u.name, u.role, r.name
        ORDER BY u.name, done DESC");
    $stmt->execute([$date]);
    $rows = $stmt->fetchAll();

    // Схлопываем в одну запись на сотрудника с разбивкой по маршрутам.
    $staff = [];
    foreach ($rows as $r) {
        $id = $r['id'];
        if (!isset($staff[$id])) {
            $staff[$id] = ['id'=>$id, 'name'=>$r['name'], 'role'=>$r['role'],
                           'total'=>0, 'routes'=>[], 'first_at'=>$r['first_at'], 'last_at'=>$r['last_at']];
        }
        $staff[$id]['total'] += (int)$r['done'];
        $staff[$id]['routes'][] = ['route'=>$r['route_name'] ?? '—', 'done'=>(int)$r['done']];
        if ($r['first_at'] < $staff[$id]['first_at']) $staff[$id]['first_at'] = $r['first_at'];
        if ($r['last_at']  > $staff[$id]['last_at'])  $staff[$id]['last_at']  = $r['last_at'];
    }
    usort($staff, fn($a, $b) => $b['total'] <=> $a['total']);

    // Сколько работы на маршруте всего и сколько закрыто — видно, где отстают.
    $rstmt = $db->prepare("
        SELECT r.name AS route_name, COUNT(*) AS total,
               SUM(t.is_completed) AS done
        FROM tasks t JOIN animals a ON t.animal_id=a.id
        LEFT JOIN routes r ON a.route_id=r.id
        WHERE t.date=? GROUP BY r.id, r.name ORDER BY r.name");
    $rstmt->execute([$date]);
    $byRoute = $rstmt->fetchAll();
    foreach ($byRoute as &$b) {
        $b['done']  = (int)$b['done'];
        $b['total'] = (int)$b['total'];
        $b['left']  = $b['total'] - $b['done'];
        $b['pct']   = $b['total'] ? round($b['done'] / $b['total'] * 100) : 0;
    }

    ok(['date' => $date, 'staff' => array_values($staff), 'by_route' => $byRoute]);
}

// ══════════════════════════════════════════════════════════════
// СПРАВОЧНИК ПРЕПАРАТОВ
// ══════════════════════════════════════════════════════════════
function ensureTemplatesTable(PDO $db): void {
    $db->exec("CREATE TABLE IF NOT EXISTS medication_templates (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        `group` VARCHAR(100),
        administration_route VARCHAR(100),
        period_type VARCHAR(50) DEFAULT 'daily',
        every_n_days INT NULL,
        cycle_config TEXT NULL,
        time_slots TEXT NULL,
        typical_dosage VARCHAR(255) NULL,
        duration_days INT NULL,
        notes TEXT NULL,
        needs_review TINYINT(1) DEFAULT 0,
        usage_count INT DEFAULT 0,
        is_active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT NOW(),
        created_by VARCHAR(36) NULL,
        UNIQUE KEY uniq_name (name),
        KEY idx_usage (usage_count)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

// Наполнение справочника из уже выписанных назначений: для каждого названия
// берём САМУЮ ЧАСТУЮ комбинацию группы, пути введения, периодичности и слота.
// Доза намеренно НЕ переносится — она считается по весу конкретного животного,
// и подставлять её из шаблона опасно.
function seedTemplates(PDO $db): array {
    ensureTemplatesTable($db);

    $rows = $db->query("
        SELECT TRIM(REGEXP_REPLACE(medication_name,'[[:space:]]+',' ')) AS name,
               COUNT(*) AS cnt
        FROM procedures
        WHERE medication_name IS NOT NULL AND TRIM(medication_name) <> ''
        GROUP BY name
        ORDER BY cnt DESC")->fetchAll();

    $pick = $db->prepare("
        SELECT `group`, administration_route, period_type, every_n_days, cycle_config, time_slots, COUNT(*) c
        FROM procedures
        WHERE TRIM(REGEXP_REPLACE(medication_name,'[[:space:]]+',' ')) = ?
        GROUP BY `group`, administration_route, period_type, every_n_days, cycle_config, time_slots
        ORDER BY c DESC LIMIT 1");

    $ins = $db->prepare("INSERT INTO medication_templates
        (id,name,`group`,administration_route,period_type,every_n_days,cycle_config,time_slots,usage_count)
        VALUES (?,?,?,?,?,?,?,?,?)
        ON DUPLICATE KEY UPDATE usage_count=VALUES(usage_count)");

    $added = 0;
    foreach ($rows as $r) {
        $pick->execute([$r['name']]);
        $best = $pick->fetch() ?: [];
        $ins->execute([
            bin2hex(random_bytes(16)), $r['name'],
            $best['group'] ?? null, $best['administration_route'] ?? null,
            $best['period_type'] ?? 'daily', $best['every_n_days'] ?? null,
            $best['cycle_config'] ?? null, $best['time_slots'] ?? null,
            (int)$r['cnt'],
        ]);
        $added++;
    }
    return ['templates' => $added];
}

function templatesHandler(string $method, ?string $id): void {
    $db = db();
    ensureTemplatesTable($db);

    if ($method === 'GET') {
        if (($_GET['action'] ?? '') === 'seed') {
            requireRole(['techAdmin', 'doctor']);
            ok(seedTemplates($db));
        }
        $where = ['is_active=1']; $params = [];
        if (!empty($_GET['search'])) { $where[] = 'name LIKE ?'; $params[] = '%' . $_GET['search'] . '%'; }
        $stmt = $db->prepare("SELECT * FROM medication_templates WHERE " . implode(' AND ', $where)
                             . " ORDER BY usage_count DESC, name LIMIT 800");
        $stmt->execute($params);
        $rows = $stmt->fetchAll();
        foreach ($rows as &$t) {
            $t['time_slots']   = decodeJson($t['time_slots']);
            $t['cycle_config'] = decodeJson($t['cycle_config']);
        }
        ok($rows);
    }

    if ($method === 'POST') {
        $b = body();
        if (empty($b['name'])) err('Не указано название препарата');
        $newId = bin2hex(random_bytes(16));
        $db->prepare("INSERT INTO medication_templates
            (id,name,`group`,administration_route,period_type,every_n_days,cycle_config,time_slots,typical_dosage,notes,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE `group`=VALUES(`group`), administration_route=VALUES(administration_route),
                period_type=VALUES(period_type), time_slots=VALUES(time_slots), notes=VALUES(notes)")
           ->execute([$newId, trim($b['name']), $b['group'] ?? null, $b['administration_route'] ?? null,
                      $b['period_type'] ?? 'daily', $b['every_n_days'] ?? null,
                      isset($b['cycle_config']) ? json_encode($b['cycle_config']) : null,
                      isset($b['time_slots']) ? json_encode($b['time_slots']) : null,
                      $b['typical_dosage'] ?? null, $b['notes'] ?? null, currentUser()['id'] ?? null]);
        logAudit($db, 'templateCreated', 'Справочник: добавлен «' . $b['name'] . '»', $newId, $b['name'], 'template');
        ok(['id' => $newId], 201);
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        if (array_key_exists('name', $b) && trim((string)$b['name']) === '') err('Название не может быть пустым');

        $cur = $db->prepare("SELECT name FROM medication_templates WHERE id=?");
        $cur->execute([$id]);
        $oldName = (string)($cur->fetchColumn() ?: '');

        $set = []; $params = [];
        foreach (['name','group','administration_route','period_type','every_n_days',
                  'typical_dosage','duration_days','notes'] as $c) {
            if (array_key_exists($c, $b)) { $set[] = "`$c`=?"; $params[] = $b[$c] === '' ? null : $b[$c]; }
        }
        foreach (['cycle_config','time_slots'] as $c) {
            if (array_key_exists($c, $b)) { $set[] = "`$c`=?"; $params[] = $b[$c] ? json_encode($b[$c]) : null; }
        }
        if (!$set) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE medication_templates SET " . implode(',', $set) . " WHERE id=?")->execute($params);

        // Переименование препарата в справочнике по желанию переносится
        // и на назначения — иначе история останется со старым написанием,
        // а именно ради единообразия справочник и заводился.
        $renamed = 0;
        if (!empty($b['rename_usages']) && !empty($b['name']) && $b['name'] !== $oldName) {
            $u = $db->prepare("UPDATE procedures SET medication_name=? WHERE TRIM(medication_name)=?");
            $u->execute([trim($b['name']), $oldName]);
            $renamed = $u->rowCount();
        }
        logAudit($db, 'templateUpdated', 'Справочник: изменён «' . ($b['name'] ?? $oldName) . '»', $id, $b['name'] ?? $oldName, 'template');
        ok(['updated' => true, 'renamed_usages' => $renamed]);
    }

    if ($method === 'DELETE' && $id) {
        // Препарат, который уже назначали, не удаляем — только скрываем:
        // иначе история назначений потеряет описание.
        $n0 = $db->prepare("SELECT name FROM medication_templates WHERE id=?");
        $n0->execute([$id]);
        $nm0 = (string)($n0->fetchColumn() ?: '');
        $used = $db->prepare("SELECT COUNT(*) FROM procedures WHERE TRIM(medication_name)=?");
        $used->execute([$nm0]);
        if ((int)$used->fetchColumn() > 0) {
            $db->prepare("UPDATE medication_templates SET is_active=0 WHERE id=?")->execute([$id]);
            logAudit($db, 'templateDeleted', 'Справочник: скрыт «' . $nm0 . '» (используется в назначениях)', $id, $nm0, 'template');
            ok(['hidden' => true, 'reason' => 'used']);
        }

        $n = $db->prepare("SELECT name FROM medication_templates WHERE id=?");
        $n->execute([$id]);
        $nm = (string)($n->fetchColumn() ?: '');
        // Мягкое удаление: препарат мог использоваться в назначениях, и терять
        // его описание из истории не нужно.
        $db->prepare("DELETE FROM medication_templates WHERE id=?")->execute([$id]);
        logAudit($db, 'templateDeleted', 'Справочник: удалён «' . $nm . '»', $id, $nm, 'template');
        ok(['deleted' => true]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// ПОИСК ПОХОЖИХ НАЗВАНИЙ (проверка дублей)
// ══════════════════════════════════════════════════════════════
// levenshtein() в PHP работает по байтам, а кириллица занимает два байта —
// расстояния получились бы завышенными. Поэтому своя реализация по символам.
function mbLevenshtein(string $a, string $b): int {
    $aa = preg_split('//u', $a, -1, PREG_SPLIT_NO_EMPTY);
    $bb = preg_split('//u', $b, -1, PREG_SPLIT_NO_EMPTY);
    $la = count($aa); $lb = count($bb);
    if ($la === 0) return $lb;
    if ($lb === 0) return $la;
    $prev = range(0, $lb);
    for ($i = 1; $i <= $la; $i++) {
        $cur = [$i];
        for ($j = 1; $j <= $lb; $j++) {
            $cost = ($aa[$i-1] === $bb[$j-1]) ? 0 : 1;
            $cur[$j] = min($prev[$j] + 1, $cur[$j-1] + 1, $prev[$j-1] + $cost);
        }
        $prev = $cur;
    }
    return $prev[$lb];
}

// ══════════════════════════════════════════════════════════════
// УНИВЕРСАЛЬНЫЙ ПОИСК И СЛИЯНИЕ ДУБЛЕЙ В СПРАВОЧНИКАХ
// ══════════════════════════════════════════════════════════════
// Все справочники страдают одним и тем же: люди вписывали названия руками,
// и одно и то же попадало в базу в нескольких написаниях. Логика поиска
// одинаковая, различается только где хранится и кто на это ссылается.
function dictConfig(string $kind): array {
    $map = [
        'meds' => [
            'label' => 'Препараты', 'table' => 'medication_templates',
            'usage' => "SELECT COUNT(*) FROM procedures WHERE TRIM(medication_name)=?",
            'merge' => ["UPDATE procedures SET medication_name=:keep WHERE TRIM(medication_name)=:drop"],
            'by_name' => true,
        ],
        'places' => [
            'label' => 'Места', 'table' => 'places',
            'usage' => "SELECT COUNT(*) FROM animals WHERE is_active=1 AND TRIM(room)=?",
            // Переименование ограничено маршрутом: одинаковое название места
            // может встречаться на разных маршрутах, и трогать чужие нельзя.
            'merge' => ["UPDATE animals SET room=:keep WHERE TRIM(room)=:drop AND route_id=:scope"],
            'by_name' => true, 'scope' => 'route_id',
        ],
        'routes' => [
            'label' => 'Маршруты', 'table' => 'routes',
            'usage' => "SELECT COUNT(*) FROM animals WHERE route_id=?",
            'merge' => ["UPDATE animals SET route_id=:keep WHERE route_id=:drop"],
            'by_name' => false,
        ],
        'vacc_types' => [
            'label' => 'Типы вакцинаций', 'table' => 'vaccination_types',
            'usage' => "SELECT COUNT(*) FROM vaccinations WHERE type_id=?",
            'merge' => ["UPDATE vaccinations SET type_id=:keep WHERE type_id=:drop"],
            'by_name' => false,
        ],
        'channels' => [
            'label' => 'Каналы пристройства', 'table' => 'placement_channels',
            'usage' => "SELECT COUNT(*) FROM animal_listings WHERE channel_id=?",
            'merge' => ["UPDATE animal_listings SET channel_id=:keep WHERE channel_id=:drop"],
            'by_name' => false,
        ],
        'diagnoses' => [
            'label' => 'Диагнозы', 'table' => 'diagnoses',
            'usage' => "SELECT COUNT(*) FROM treatment_diagnoses WHERE diagnosis_id=?",
            // Слияние правит и основной диагноз случая, и связку. В связке
            // возможен конфликт первичного ключа, если оба диагноза уже стоят
            // на одном случае, — поэтому IGNORE, затем удаляем остаток.
            'merge' => [
                "UPDATE treatments SET diagnosis_id=:keep WHERE diagnosis_id=:drop",
                "UPDATE IGNORE treatment_diagnoses SET diagnosis_id=:keep WHERE diagnosis_id=:drop",
                "DELETE FROM treatment_diagnoses WHERE diagnosis_id=:drop",
            ],
            'by_name' => false,
        ],
        'statuses' => [
            'label' => 'Статусы пристройства', 'table' => 'placement_statuses',
            'usage' => "SELECT COUNT(*) FROM animal_placement WHERE status_id=?",
            'merge' => ["UPDATE animal_placement SET status_id=:keep WHERE status_id=:drop"],
            'by_name' => false,
        ],
    ];
    if (!isset($map[$kind])) err('Неизвестный справочник: ' . $kind, 400);
    return $map[$kind];
}

// Нормализация для сравнения: регистр, пробелы, знаки — не различия.
// Числа выносим отдельно: «Гапентин 80 мг» и «Гапентин 400 мг» — разные
// дозировки, и объединять их нельзя ни при каких условиях.
function dictNormalize(string $name): array {
    $low = mb_strtolower(trim($name), 'UTF-8');
    preg_match_all('/\d+[.,]?\d*/u', $low, $m);
    return [
        'digits' => implode(',', $m[0]),
        'core'   => preg_replace('/[^\p{L}]/u', '', $low),
        'head'   => trim(preg_replace('/\(.*$/u', '', $low)),
    ];
}

function dictDuplicatesHandler(): void {
    $db = db();
    $kind = $_GET['kind'] ?? 'meds';
    $cfg  = dictConfig($kind);

    ensurePlacesTable($db); ensureRouteColumns($db);
    ensureVaccinationTables($db); ensurePlacementTables($db); ensureTemplatesTable($db);

    $scope = $cfg['scope'] ?? null;
    $cols  = 'id, name' . ($scope ? ", $scope AS scope" : '');
    $rows  = $db->query("SELECT $cols FROM {$cfg['table']} WHERE is_active=1")->fetchAll();

    // Сколько записей ссылается на каждую позицию — показываем, чтобы было
    // видно, какую из пары оставлять главной.
    $u = $db->prepare($cfg['usage']);
    foreach ($rows as &$r) {
        $u->execute([$cfg['by_name'] ? $r['name'] : $r['id']]);
        $r['usage'] = (int)$u->fetchColumn();
        $r['norm'] = dictNormalize($r['name']);
    }
    unset($r);

    $pairs = [];
    $n = count($rows);
    for ($i = 0; $i < $n; $i++) {
        for ($j = $i + 1; $j < $n; $j++) {
            $a = $rows[$i]; $b = $rows[$j];
            // Места сравниваем только внутри одного маршрута.
            if ($scope && $a['scope'] !== $b['scope']) continue;
            if ($a['norm']['digits'] !== $b['norm']['digits']) continue;
            if ($a['norm']['core'] === '' || $b['norm']['core'] === '') continue;

            // Уверенность важнее самого факта совпадения: «Травма 2» и
            // «Травма2» — точно одно, а «под стелажом» и «середина стеллажа» —
            // разные полки, хоть начало и общее. Без градации человек рискует
            // слить оптом то, что сливать нельзя.
            $reason = null; $confidence = null;
            if ($a['norm']['core'] === $b['norm']['core']) {
                $reason = 'отличаются только регистром, пробелами или знаками';
                $confidence = 'high';
            } else {
                $la = mb_strlen($a['norm']['core']); $lb = mb_strlen($b['norm']['core']);
                if (min($la, $lb) >= 4) {
                    $d = mbLevenshtein($a['norm']['core'], $b['norm']['core']);
                    if ($d > 0 && $d <= 2) { $reason = "похоже на опечатку (различий: $d)"; $confidence = 'medium'; }
                }
                if (!$reason && $a['norm']['head'] !== '' && $a['norm']['head'] === $b['norm']['head']) {
                    $reason = 'одинаковое начало, разное уточнение в скобках — возможно, это РАЗНЫЕ записи';
                    $confidence = 'low';
                }
                if (!$reason && min($la, $lb) >= 4 &&
                    (str_contains($a['norm']['core'], $b['norm']['core']) || str_contains($b['norm']['core'], $a['norm']['core'])) &&
                    abs($la - $lb) <= 12) {
                    $reason = 'одно название входит в другое — возможно, это РАЗНЫЕ записи';
                    $confidence = 'low';
                }
            }
            if ($reason) {
                // Первой ставим ту, что используется чаще — её логично оставить.
                $keep = $a['usage'] >= $b['usage'] ? $a : $b;
                $drop = $a['usage'] >= $b['usage'] ? $b : $a;
                $pairs[] = [
                    'keep_id' => $keep['id'], 'keep_name' => $keep['name'], 'keep_usage' => $keep['usage'],
                    'drop_id' => $drop['id'], 'drop_name' => $drop['name'], 'drop_usage' => $drop['usage'],
                    'reason' => $reason, 'confidence' => $confidence,
                ];
            }
        }
    }
    $rank = ['high' => 0, 'medium' => 1, 'low' => 2];
    usort($pairs, fn($x, $y) => [$rank[$x['confidence']], -($x['keep_usage'] + $x['drop_usage'])]
                            <=> [$rank[$y['confidence']], -($y['keep_usage'] + $y['drop_usage'])]);
    $counts = ['high' => 0, 'medium' => 0, 'low' => 0];
    foreach ($pairs as $pp) $counts[$pp['confidence']]++;
    ok(['kind' => $kind, 'label' => $cfg['label'], 'total' => $n, 'pairs' => $pairs, 'counts' => $counts]);
}

// Слияние: переносим все ссылки на оставляемую позицию и убираем лишнюю.
function dictMergeHandler(): void {
    $db = db();
    $b  = body();
    $kind = $b['kind'] ?? '';
    $cfg  = dictConfig($kind);

    $keepId = $b['keep_id'] ?? null;
    $dropId = $b['drop_id'] ?? null;
    if (!$keepId || !$dropId || $keepId === $dropId) err('Не указаны записи для слияния');

    $get = $db->prepare("SELECT id, name FROM {$cfg['table']} WHERE id=?");
    $get->execute([$keepId]); $keep = $get->fetch();
    $get->execute([$dropId]); $drop = $get->fetch();
    if (!$keep || !$drop) err('Запись не найдена', 404);

    $db->beginTransaction();
    try {
        // Область действия: для мест — маршрут, к которому они привязаны.
        $scopeVal = null;
        if (!empty($cfg['scope'])) {
            $sc = $db->prepare("SELECT {$cfg['scope']} FROM {$cfg['table']} WHERE id=?");
            $sc->execute([$dropId]);
            $scopeVal = $sc->fetchColumn();
        }

        // Для справочников по названию переносим по тексту, иначе по id.
        $params = $cfg['by_name']
            ? [':keep' => $keep['name'], ':drop' => $drop['name']]
            : [':keep' => $keep['id'],   ':drop' => $drop['id']];

        $moved = 0;
        foreach ($cfg['merge'] as $sql) {
            // Передаём только те параметры, которые реально есть в запросе:
            // лишний именованный параметр PDO считает ошибкой (HY093).
            $args = [];
            foreach ($params as $k => $v) if (str_contains($sql, $k)) $args[$k] = $v;
            if (str_contains($sql, ':scope')) $args[':scope'] = $scopeVal;
            $st = $db->prepare($sql);
            $st->execute($args);
            $moved += $st->rowCount();
        }
        // Лишнюю позицию не удаляем, а скрываем: на неё могут ссылаться
        // исторические записи, которые мы намеренно не трогаем.
        $db->prepare("UPDATE {$cfg['table']} SET is_active=0 WHERE id=?")->execute([$dropId]);
        logAudit($db, 'other', "Справочник «{$cfg['label']}»: «{$drop['name']}» объединено с «{$keep['name']}», перенесено записей: $moved",
                 $keepId, $keep['name'], 'dictionary');
        $db->commit();
        ok(['merged' => true, 'moved' => $moved, 'keep' => $keep['name'], 'dropped' => $drop['name']]);
    } catch (Exception $e) {
        $db->rollBack();
        throw $e;
    }
}

function medDuplicatesHandler(): void {
    $db = db();
    $rows = $db->query("
        SELECT TRIM(REGEXP_REPLACE(medication_name,'[[:space:]]+',' ')) AS name, COUNT(*) cnt
        FROM procedures WHERE medication_name IS NOT NULL AND TRIM(medication_name) <> ''
        GROUP BY name")->fetchAll();

    $items = [];
    foreach ($rows as $r) {
        $low  = mb_strtolower($r['name'], 'UTF-8');
        // Числа выносим отдельно: «Гапентин 80 мг» и «Гапентин 400 мг» —
        // РАЗНЫЕ дозировки препарата, объединять их нельзя.
        preg_match_all('/\d+[.,]?\d*/u', $low, $m);
        $digits = implode(',', $m[0]);
        $core   = preg_replace('/[^\p{L}]/u', '', $low);          // только буквы
        $head   = trim(preg_replace('/\(.*$/u', '', $low));        // до первой скобки
        $items[] = ['name' => $r['name'], 'cnt' => (int)$r['cnt'],
                    'digits' => $digits, 'core' => $core, 'head' => $head];
    }

    $pairs = [];
    $n = count($items);
    for ($i = 0; $i < $n; $i++) {
        for ($j = $i + 1; $j < $n; $j++) {
            $a = $items[$i]; $b = $items[$j];

            // Разные числа — считаем разными препаратами и не предлагаем.
            if ($a['digits'] !== $b['digits']) continue;
            if ($a['core'] === '' || $b['core'] === '') continue;

            $reason = null;
            if ($a['core'] === $b['core']) {
                $reason = 'отличаются только пробелами, регистром или знаками';
            } elseif ($a['head'] !== '' && $a['head'] === $b['head']) {
                $reason = 'одинаковое начало, разное уточнение в скобках';
            } else {
                $lenA = mb_strlen($a['core']); $lenB = mb_strlen($b['core']);
                $len  = min($lenA, $lenB);
                if ($len >= 5) {
                    $d = mbLevenshtein($a['core'], $b['core']);
                    if ($d > 0 && $d <= 2) {
                        $reason = "похожи на опечатку (различий: $d)";
                    } elseif (str_contains($a['core'], $b['core']) || str_contains($b['core'], $a['core'])) {
                        // Вхождение засчитываем, только если строки сопоставимы по длине.
                        // Иначе в дубли попадала бы любая длинная инструкция,
                        // где случайно упомянут препарат: «Неванак» и
                        // «Протирать глаза фурацилином, после этого капать неванак».
                        if (max($lenA, $lenB) - $len <= 12) {
                            $reason = 'одно название полностью входит в другое';
                        }
                    }
                }
            }
            if ($reason) {
                $pairs[] = [
                    'a' => $a['name'], 'a_count' => $a['cnt'],
                    'b' => $b['name'], 'b_count' => $b['cnt'],
                    'reason' => $reason,
                ];
            }
        }
    }
    usort($pairs, fn($x, $y) => ($y['a_count'] + $y['b_count']) <=> ($x['a_count'] + $x['b_count']));
    ok(['pairs' => $pairs, 'names_total' => $n]);
}

// ══════════════════════════════════════════════════════════════
// ПРИСТРОЙСТВО: статусы животных
// ══════════════════════════════════════════════════════════════
// Статусы — справочник, а не зашитый список: процесс приюта меняется,
// и добавить «на передержке» или убрать лишнее должно быть можно без правки кода.
function ensurePlacementTables(PDO $db): void {
    static $done = false;
    if ($done) return;
    $done = true;

    $db->exec("CREATE TABLE IF NOT EXISTS placement_statuses (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        color VARCHAR(20) DEFAULT '#9E9E9E',
        sort_order INT DEFAULT 0,
        is_active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT NOW(),
        UNIQUE KEY uniq_name (name),
        KEY idx_sort (sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Данные пристройства по животному: одна строка на животное.
    $db->exec("CREATE TABLE IF NOT EXISTS animal_placement (
        animal_id VARCHAR(36) PRIMARY KEY,
        status_id VARCHAR(36) NULL,
        status_since DATE NULL,
        status_until DATE NULL,
        status_note TEXT NULL,
        med_summary TEXT NULL,
        housing VARCHAR(30) NULL,
        ok_with_cats VARCHAR(20) NULL,
        ok_with_dogs VARCHAR(20) NULL,
        ok_with_kids VARCHAR(20) NULL,
        character_note TEXT NULL,
        behaviour_note TEXT NULL,
        updated_at DATETIME DEFAULT NOW(),
        updated_by VARCHAR(36) NULL,
        KEY idx_status (status_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // История смен статуса — чтобы видеть путь животного и считать воронку.
    $db->exec("CREATE TABLE IF NOT EXISTS placement_status_history (
        id VARCHAR(36) PRIMARY KEY,
        animal_id VARCHAR(36) NOT NULL,
        from_status VARCHAR(100) NULL,
        to_status VARCHAR(100) NULL,
        note TEXT NULL,
        changed_at DATETIME DEFAULT NOW(),
        user_id VARCHAR(36) NULL,
        user_name VARCHAR(255) NULL,
        KEY idx_animal (animal_id),
        KEY idx_changed (changed_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Признак «уязвимое»: хроника, возраст. По негласному правилу приюта такие
    // животные не размещаются на Авито и в газетах — там их не ищут.
    $has = $db->query("SELECT COUNT(*) FROM information_schema.columns
                       WHERE table_schema=DATABASE() AND table_name='animal_placement' AND column_name='is_vulnerable'")->fetchColumn();
    if (!$has) $db->exec("ALTER TABLE animal_placement ADD COLUMN is_vulnerable TINYINT(1) DEFAULT 0");

    $db->exec("CREATE TABLE IF NOT EXISTS placement_channels (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(150) NOT NULL,
        kind VARCHAR(30) DEFAULT 'other',
        is_paid TINYINT(1) DEFAULT 0,
        cost DECIMAL(10,2) NULL,
        cost_period VARCHAR(20) NULL,
        region VARCHAR(150) NULL,
        owner_name VARCHAR(150) NULL,
        refresh_days INT NULL,
        allow_vulnerable TINYINT(1) DEFAULT 1,
        tracking_tag VARCHAR(60) NULL,
        notes TEXT NULL,
        sort_order INT DEFAULT 0,
        is_active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT NOW(),
        UNIQUE KEY uniq_name (name),
        KEY idx_sort (sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Размещение = животное на конкретной площадке.
    $db->exec("CREATE TABLE IF NOT EXISTS animal_listings (
        id VARCHAR(36) PRIMARY KEY,
        animal_id VARCHAR(36) NOT NULL,
        channel_id VARCHAR(36) NOT NULL,
        posted_at DATE NULL,
        url TEXT NULL,
        issue_ref VARCHAR(150) NULL,
        status VARCHAR(20) DEFAULT 'active',
        last_update DATE NULL,
        next_update DATE NULL,
        views INT NULL,
        responses INT DEFAULT 0,
        note TEXT NULL,
        created_by VARCHAR(36) NULL,
        created_at DATETIME DEFAULT NOW(),
        updated_at DATETIME DEFAULT NOW(),
        UNIQUE KEY uniq_listing (animal_id, channel_id),
        KEY idx_channel (channel_id),
        KEY idx_next (next_update),
        KEY idx_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    if ((int)$db->query("SELECT COUNT(*) FROM placement_channels")->fetchColumn() === 0) {
        // Наполнено по совещанию: что реально используется и на каких условиях.
        $ch = [
            // название, вид, платный, стоимость, период, район, кто ведёт, обновлять раз в N дней, можно уязвимых
            ['Доска объявлений — аккаунт фонда','marketplace',0,null,null,null,'Администраторы',null,0,'Автопродление. Новые фото вешает администратор'],
            ['Газеты областные','print',1,41000,'месяц','Область','Админы отправляют, звонки — координатор',7,0,'2–3 объявления в каждую газету еженедельно'],
            ['Городская газета','print',1,null,null,'Город','Администраторы',7,0,'Исключение: звонки идут напрямую администраторам'],
            ['ВКонтакте','social',0,null,null,null,'SMM-волонтёр',null,1,null],
            ['Инстаграм','social',0,null,null,null,'SMM-волонтёр',null,1,null],
            ['Телеграм','social',0,null,null,null,'SMM-волонтёр',null,1,null],
            ['Сайт фонда','site',0,null,null,null,'—',null,1,'Страница «Взять животное в семью». Актуального списка пока нет'],
            ['Личный приход в приют','offline',0,null,null,'Город','Администраторы',null,1,null],
            ['Локальные городские паблики','social',null,null,null,'Город','—',null,1,'Не используется. Условия и цены не выяснены'],
            ['Колл-центр (аутсорс)','phone',1,9990,'месяц',null,'—',null,1,'Заявка подана. Скрипты, запись разговоров, отчётность'],
        ];
        $ins = $db->prepare("INSERT INTO placement_channels
            (id,name,kind,is_paid,cost,cost_period,region,owner_name,refresh_days,allow_vulnerable,notes,sort_order)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
        $i = 10;
        foreach ($ch as $c) {
            $ins->execute([bin2hex(random_bytes(16)), $c[0], $c[1], $c[2], $c[3], $c[4], $c[5], $c[6], $c[7], $c[8], $c[9], $i]);
            $i += 10;
        }
    }

    // Первичное наполнение — только если справочник пуст.
    $cnt = (int)$db->query("SELECT COUNT(*) FROM placement_statuses")->fetchColumn();
    if ($cnt === 0) {
        $seed = [
            ['Поступил',        '#90A4AE', 10],
            ['Карантин',        '#FF9800', 20],
            ['Лечится',         '#EF5350', 30],
            ['Здоров',          '#66BB6A', 40],
            ['Готов к пиару',   '#26C6DA', 50],
            ['В пиаре',         '#42A5F5', 60],
            ['На стопе',        '#8D6E63', 70],
            ['Уехал домой',     '#7E57C2', 80],
            ['Вернули',         '#EC407A', 90],
        ];
        $ins = $db->prepare("INSERT INTO placement_statuses (id,name,color,sort_order) VALUES (?,?,?,?)");
        foreach ($seed as $s) $ins->execute([bin2hex(random_bytes(16)), $s[0], $s[1], $s[2]]);
    }
}

function placementStatusesHandler(string $method, ?string $id): void {
    $db = db();
    ensurePlacementTables($db);

    if ($method === 'GET') {
        $rows = $db->query("SELECT s.*, (SELECT COUNT(*) FROM animal_placement p JOIN animals a ON p.animal_id=a.id
                                         WHERE p.status_id=s.id AND a.is_active=1) AS animals_count
                            FROM placement_statuses s
                            WHERE s.is_active=1 ORDER BY s.sort_order, s.name")->fetchAll();
        ok($rows);
    }

    if ($method === 'POST') {
        $b = body();
        if (empty($b['name'])) err('Не указано название статуса');
        $newId = bin2hex(random_bytes(16));
        $max = (int)$db->query("SELECT COALESCE(MAX(sort_order),0) FROM placement_statuses")->fetchColumn();
        $db->prepare("INSERT INTO placement_statuses (id,name,color,sort_order) VALUES (?,?,?,?)
                      ON DUPLICATE KEY UPDATE is_active=1, color=VALUES(color)")
           ->execute([$newId, trim($b['name']), $b['color'] ?? '#9E9E9E', $b['sort_order'] ?? $max + 10]);
        logAudit($db, 'other', 'Пристройство: добавлен статус «' . $b['name'] . '»', $newId, $b['name'], 'status');
        ok(['id' => $newId], 201);
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        $fields = []; $params = [];
        foreach (['name','color','sort_order'] as $f) {
            if (array_key_exists($f, $b)) { $fields[] = "`$f`=?"; $params[] = $b[$f]; }
        }
        if (!$fields) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE placement_statuses SET " . implode(',', $fields) . " WHERE id=?")->execute($params);
        ok(['updated' => true]);
    }

    if ($method === 'DELETE' && $id) {
        // Статус, на котором стоят животные, не убираем молча — иначе они
        // окажутся без статуса, и воронка соврёт.
        $c = $db->prepare("SELECT COUNT(*) FROM animal_placement p JOIN animals a ON p.animal_id=a.id
                           WHERE p.status_id=? AND a.is_active=1");
        $c->execute([$id]);
        $n = (int)$c->fetchColumn();
        if ($n > 0) err("На этом статусе сейчас $n живот. Сначала переведите их на другой статус.");

        $nm = $db->prepare("SELECT name FROM placement_statuses WHERE id=?");
        $nm->execute([$id]);
        $name = (string)($nm->fetchColumn() ?: '');
        // История смен статуса хранит названия текстом, поэтому статус,
        // который нигде не проставлен, можно удалить совсем.
        $used = $db->prepare("SELECT COUNT(*) FROM animal_placement WHERE status_id=?");
        $used->execute([$id]);
        if ((int)$used->fetchColumn() > 0) {
            $db->prepare("UPDATE placement_statuses SET is_active=0 WHERE id=?")->execute([$id]);
        } else {
            $db->prepare("DELETE FROM placement_statuses WHERE id=?")->execute([$id]);
        }
        logAudit($db, 'other', 'Пристройство: убран статус «' . $name . '»', $id, $name, 'status');
        ok(['deleted' => true]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// ПРИСТРОЙСТВО: данные животного
// ══════════════════════════════════════════════════════════════
function placementHandler(string $method, ?string $id): void {
    $db = db();
    ensurePlacementTables($db);

    if ($method === 'GET') {
        // Сводка по воронке
        if (($_GET['view'] ?? '') === 'funnel') {
            $rows = $db->query("
                SELECT s.id, s.name, s.color, s.sort_order,
                       COUNT(a.id) AS cnt
                FROM placement_statuses s
                LEFT JOIN animal_placement p ON p.status_id = s.id
                LEFT JOIN animals a ON a.id = p.animal_id AND a.is_active = 1
                WHERE s.is_active = 1
                GROUP BY s.id, s.name, s.color, s.sort_order
                ORDER BY s.sort_order")->fetchAll();
            $noStatus = (int)$db->query("
                SELECT COUNT(*) FROM animals a
                LEFT JOIN animal_placement p ON p.animal_id = a.id
                WHERE a.is_active = 1 AND (p.status_id IS NULL)")->fetchColumn();
            ok(['funnel' => $rows, 'without_status' => $noStatus]);
        }

        // Данные одного животного
        if ($id) {
            $stmt = $db->prepare("SELECT p.*, s.name AS status_name, s.color AS status_color
                                  FROM animal_placement p LEFT JOIN placement_statuses s ON p.status_id=s.id
                                  WHERE p.animal_id=?");
            $stmt->execute([$id]);
            $row = $stmt->fetch() ?: ['animal_id' => $id];

            $h = $db->prepare("SELECT from_status,to_status,note,changed_at,user_name
                               FROM placement_status_history WHERE animal_id=? ORDER BY changed_at DESC LIMIT 30");
            $h->execute([$id]);
            $row['history'] = $h->fetchAll();
            ok($row);
        }

        // Список животных с фильтрами по параметрам пристройства
        $where = ['a.is_active=1']; $params = [];
        foreach (['status_id' => 'p.status_id', 'housing' => 'p.housing',
                  'ok_with_cats' => 'p.ok_with_cats', 'ok_with_dogs' => 'p.ok_with_dogs',
                  'ok_with_kids' => 'p.ok_with_kids'] as $q => $col) {
            if (!empty($_GET[$q])) { $where[] = "$col=?"; $params[] = $_GET[$q]; }
        }
        if (!empty($_GET['species'])) { $where[] = 'a.species=?'; $params[] = $_GET['species']; }
        if (!empty($_GET['search']))  { $where[] = 'a.name LIKE ?'; $params[] = '%' . $_GET['search'] . '%'; }

        $stmt = $db->prepare("SELECT a.id, a.name, a.species, a.gender, a.room, r.name AS route_name,
                                     p.status_id, p.status_since, p.status_until, p.status_note,
                                     p.med_summary, p.housing, p.ok_with_cats, p.ok_with_dogs, p.ok_with_kids,
                                     p.character_note, s.name AS status_name, s.color AS status_color
                              FROM animals a
                              LEFT JOIN animal_placement p ON p.animal_id=a.id
                              LEFT JOIN placement_statuses s ON p.status_id=s.id
                              LEFT JOIN routes r ON a.route_id=r.id
                              WHERE " . implode(' AND ', $where) . "
                              ORDER BY s.sort_order, a.name LIMIT 500");
        $stmt->execute($params);
        ok($stmt->fetchAll());
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        $actor = currentUser();

        $cur = $db->prepare("SELECT p.status_id, s.name AS status_name FROM animal_placement p
                             LEFT JOIN placement_statuses s ON p.status_id=s.id WHERE p.animal_id=?");
        $cur->execute([$id]);
        $before = $cur->fetch() ?: [];

        $cols = ['status_id','status_since','status_until','status_note','med_summary','housing',
                 'ok_with_cats','ok_with_dogs','ok_with_kids','character_note','behaviour_note','is_vulnerable'];
        $set = []; $params = [];
        foreach ($cols as $c) if (array_key_exists($c, $b)) { $set[] = "$c=?"; $params[] = $b[$c] === '' ? null : $b[$c]; }
        if (!$set) err('Nothing to update');

        // Смена статуса всегда проставляет дату — иначе не посчитать,
        // сколько животное стоит на карантине или висит в пиаре.
        $statusChanged = array_key_exists('status_id', $b) && ($before['status_id'] ?? null) !== $b['status_id'];
        if ($statusChanged && !array_key_exists('status_since', $b)) { $set[] = 'status_since=CURDATE()'; }

        $set[] = 'updated_at=NOW()'; $set[] = 'updated_by=?'; $params[] = $actor['id'] ?? null;

        $exists = $db->prepare("SELECT COUNT(*) FROM animal_placement WHERE animal_id=?");
        $exists->execute([$id]);
        if ((int)$exists->fetchColumn() === 0) {
            $db->prepare("INSERT INTO animal_placement (animal_id) VALUES (?)")->execute([$id]);
        }
        $params[] = $id;
        $db->prepare("UPDATE animal_placement SET " . implode(',', $set) . " WHERE animal_id=?")->execute($params);

        if ($statusChanged) {
            $nm = $db->prepare("SELECT name FROM placement_statuses WHERE id=?");
            $nm->execute([$b['status_id']]);
            $toName = (string)($nm->fetchColumn() ?: '');
            $an = $db->prepare("SELECT name FROM animals WHERE id=?");
            $an->execute([$id]);
            $animalName = (string)($an->fetchColumn() ?: '');

            $db->prepare("INSERT INTO placement_status_history (id,animal_id,from_status,to_status,note,user_id,user_name)
                          VALUES (?,?,?,?,?,?,?)")
               ->execute([bin2hex(random_bytes(16)), $id, $before['status_name'] ?? null, $toName,
                          $b['status_note'] ?? null, $actor['id'] ?? null, $actor['name'] ?? null]);
            logAudit($db, 'other', 'Пристройство: ' . $animalName . ' — статус «' . ($before['status_name'] ?? 'не задан') . '» → «' . $toName . '»',
                     $id, $animalName, 'animal');
        }
        ok(['updated' => true, 'status_changed' => $statusChanged]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// ПРИСТРОЙСТВО: справочник каналов
// ══════════════════════════════════════════════════════════════
function channelsHandler(string $method, ?string $id): void {
    $db = db();
    ensurePlacementTables($db);

    if ($method === 'GET') {
        $rows = $db->query("
            SELECT c.*,
                   (SELECT COUNT(*) FROM animal_listings l JOIN animals a ON l.animal_id=a.id
                    WHERE l.channel_id=c.id AND l.status='active' AND a.is_active=1) AS active_listings,
                   (SELECT COUNT(*) FROM animal_listings l JOIN animals a ON l.animal_id=a.id
                    WHERE l.channel_id=c.id AND l.status='active' AND a.is_active=1
                      AND l.next_update IS NOT NULL AND l.next_update <= CURDATE()) AS need_update
            FROM placement_channels c WHERE c.is_active=1
            ORDER BY c.sort_order, c.name")->fetchAll();
        ok($rows);
    }

    if ($method === 'POST' || ($method === 'PUT' && $id)) {
        $b = body();
        if ($method === 'POST' && empty($b['name'])) err('Не указано название канала');

        $cols = ['name','kind','is_paid','cost','cost_period','region','owner_name',
                 'refresh_days','allow_vulnerable','tracking_tag','notes','sort_order'];
        if ($method === 'POST') {
            $newId = bin2hex(random_bytes(16));
            $max = (int)$db->query("SELECT COALESCE(MAX(sort_order),0) FROM placement_channels")->fetchColumn();
            $db->prepare("INSERT INTO placement_channels (id,name,kind,is_paid,cost,cost_period,region,owner_name,refresh_days,allow_vulnerable,tracking_tag,notes,sort_order)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                          ON DUPLICATE KEY UPDATE is_active=1")
               ->execute([$newId, trim($b['name']), $b['kind'] ?? 'other', (int)($b['is_paid'] ?? 0),
                          $b['cost'] ?: null, $b['cost_period'] ?: null, $b['region'] ?: null, $b['owner_name'] ?: null,
                          $b['refresh_days'] ?: null, (int)($b['allow_vulnerable'] ?? 1),
                          $b['tracking_tag'] ?: null, $b['notes'] ?: null, $b['sort_order'] ?? $max + 10]);
            logAudit($db, 'other', 'Пристройство: добавлен канал «' . $b['name'] . '»', $newId, $b['name'], 'channel');
            ok(['id' => $newId], 201);
        }

        $set = []; $params = [];
        foreach ($cols as $c) if (array_key_exists($c, $b)) { $set[] = "$c=?"; $params[] = $b[$c] === '' ? null : $b[$c]; }
        if (!$set) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE placement_channels SET " . implode(',', $set) . " WHERE id=?")->execute($params);
        ok(['updated' => true]);
    }

    if ($method === 'DELETE' && $id) {
        $c = $db->prepare("SELECT COUNT(*) FROM animal_listings WHERE channel_id=? AND status='active'");
        $c->execute([$id]);
        $n = (int)$c->fetchColumn();
        if ($n > 0) err("На этом канале $n активных размещений. Сначала снимите их.");
        $nm = $db->prepare("SELECT name FROM placement_channels WHERE id=?");
        $nm->execute([$id]);
        $name = (string)($nm->fetchColumn() ?: '');
        $db->prepare("UPDATE placement_channels SET is_active=0 WHERE id=?")->execute([$id]);
        logAudit($db, 'other', 'Пристройство: канал «' . $name . '» убран из активных', $id, $name, 'channel');
        ok(['deleted' => true]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// ПРИСТРОЙСТВО: размещения животного по каналам
// ══════════════════════════════════════════════════════════════
function listingsHandler(string $method, ?string $id): void {
    $db = db();
    ensurePlacementTables($db);

    if ($method === 'GET') {
        // Что пора обновить — рабочий список координатора.
        if (($_GET['view'] ?? '') === 'due') {
            $stmt = $db->query("
                SELECT l.*, a.name AS animal_name, c.name AS channel_name, c.kind
                FROM animal_listings l
                JOIN animals a ON l.animal_id=a.id AND a.is_active=1
                JOIN placement_channels c ON l.channel_id=c.id
                WHERE l.status='active' AND l.next_update IS NOT NULL AND l.next_update <= CURDATE()
                ORDER BY l.next_update, a.name LIMIT 300");
            ok($stmt->fetchAll());
        }

        // Готовы к пиару, но нигде не размещены.
        if (($_GET['view'] ?? '') === 'unlisted') {
            $stmt = $db->query("
                SELECT a.id, a.name, a.species, r.name AS route_name, s.name AS status_name, p.status_since
                FROM animals a
                JOIN animal_placement p ON p.animal_id=a.id
                JOIN placement_statuses s ON p.status_id=s.id
                LEFT JOIN routes r ON a.route_id=r.id
                WHERE a.is_active=1 AND s.name IN ('Готов к пиару','В пиаре')
                  AND NOT EXISTS (SELECT 1 FROM animal_listings l WHERE l.animal_id=a.id AND l.status='active')
                ORDER BY p.status_since, a.name LIMIT 300");
            ok($stmt->fetchAll());
        }

        if ($id) {
            $stmt = $db->prepare("
                SELECT l.*, c.name AS channel_name, c.kind, c.refresh_days, c.is_paid
                FROM animal_listings l JOIN placement_channels c ON l.channel_id=c.id
                WHERE l.animal_id=? ORDER BY c.sort_order");
            $stmt->execute([$id]);
            ok($stmt->fetchAll());
        }
        err('Не указано животное', 400);
    }

    if ($method === 'POST') {
        $b = body();
        $animalId  = $b['animal_id']  ?? null;
        $channelId = $b['channel_id'] ?? null;
        if (!$animalId || !$channelId) err('Не указано животное или канал');

        $ch = $db->prepare("SELECT * FROM placement_channels WHERE id=?");
        $ch->execute([$channelId]);
        $channel = $ch->fetch();
        if (!$channel) err('Канал не найден', 404);

        // Проверки из регламента приюта. Обе — предупреждения, а не запреты:
        // решение остаётся за человеком, но вслепую ошибиться он не должен.
        $warn = [];
        $pl = $db->prepare("SELECT p.is_vulnerable, s.name AS status_name
                            FROM animal_placement p LEFT JOIN placement_statuses s ON p.status_id=s.id
                            WHERE p.animal_id=?");
        $pl->execute([$animalId]);
        $info = $pl->fetch() ?: [];

        if (!empty($info['is_vulnerable']) && (int)$channel['allow_vulnerable'] === 0) {
            $warn[] = 'Животное отмечено как сложное к пристройству, а этот канал для таких не используется.';
        }
        if (in_array($info['status_name'] ?? '', ['Поступил', 'Карантин', 'Лечится'], true)) {
            $warn[] = 'Животное в статусе «' . $info['status_name'] . '» — оно ещё не готово к пиару.';
        }
        if ($warn && empty($b['force'])) {
            err(implode(' ', $warn) . ' Разместить всё равно?', 409);
        }

        $posted = $b['posted_at'] ?? date('Y-m-d');
        // Дату следующего обновления считаем из периодичности канала: у газет
        // это неделя, у Авито автопродление и обновлять не нужно.
        $next = null;
        if (!empty($channel['refresh_days'])) {
            $d = new DateTime($posted); $d->modify('+' . (int)$channel['refresh_days'] . ' days');
            $next = $d->format('Y-m-d');
        }

        $newId = bin2hex(random_bytes(16));
        $db->prepare("INSERT INTO animal_listings (id,animal_id,channel_id,posted_at,url,issue_ref,status,last_update,next_update,note,created_by)
                      VALUES (?,?,?,?,?,?,'active',?,?,?,?)
                      ON DUPLICATE KEY UPDATE status='active', posted_at=VALUES(posted_at), url=VALUES(url),
                        issue_ref=VALUES(issue_ref), last_update=VALUES(last_update), next_update=VALUES(next_update),
                        note=VALUES(note), updated_at=NOW()")
           ->execute([$newId, $animalId, $channelId, $posted, $b['url'] ?: null, $b['issue_ref'] ?: null,
                      $posted, $next, $b['note'] ?: null, currentUser()['id'] ?? null]);

        $an = $db->prepare("SELECT name FROM animals WHERE id=?"); $an->execute([$animalId]);
        logAudit($db, 'other', 'Размещение: ' . (string)$an->fetchColumn() . ' → ' . $channel['name'], $animalId, $channel['name'], 'listing');
        ok(['id' => $newId, 'next_update' => $next, 'warnings' => $warn], 201);
    }

    if ($method === 'PUT' && $id) {
        $b = body();
        // «Обновил объявление» — сдвигаем срок следующего обновления.
        if (($b['action'] ?? '') === 'refresh') {
            $l = $db->prepare("SELECT l.channel_id, c.refresh_days FROM animal_listings l
                               JOIN placement_channels c ON l.channel_id=c.id WHERE l.id=?");
            $l->execute([$id]);
            $row = $l->fetch();
            $next = null;
            if ($row && !empty($row['refresh_days'])) {
                $d = new DateTime(); $d->modify('+' . (int)$row['refresh_days'] . ' days');
                $next = $d->format('Y-m-d');
            }
            $db->prepare("UPDATE animal_listings SET last_update=CURDATE(), next_update=?, status='active', updated_at=NOW() WHERE id=?")
               ->execute([$next, $id]);
            ok(['refreshed' => true, 'next_update' => $next]);
        }

        $set = []; $params = [];
        foreach (['status','url','issue_ref','views','responses','note','posted_at','next_update'] as $c) {
            if (array_key_exists($c, $b)) { $set[] = "$c=?"; $params[] = $b[$c] === '' ? null : $b[$c]; }
        }
        if (!$set) err('Nothing to update');
        $set[] = 'updated_at=NOW()';
        $params[] = $id;
        $db->prepare("UPDATE animal_listings SET " . implode(',', $set) . " WHERE id=?")->execute($params);
        ok(['updated' => true]);
    }

    if ($method === 'DELETE' && $id) {
        $db->prepare("UPDATE animal_listings SET status='removed', updated_at=NOW() WHERE id=?")->execute([$id]);
        ok(['removed' => true]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// ВАКЦИНАЦИИ И ОБРАБОТКИ (ТЗ v3.2, раздел 8)
// ══════════════════════════════════════════════════════════════
function ensureVaccinationTables(PDO $db): void {
    static $done = false;
    if ($done) return;
    $done = true;

    // Поля карточки из раздела 9.1. Добавляем все сразу: колонки дешёвые,
    // а заполняться будут по мере работы.
    $cols = $db->query("SHOW COLUMNS FROM animals")->fetchAll(PDO::FETCH_COLUMN);
    $add = [
        'deactivation_reason' => 'VARCHAR(50) NULL',
        'deactivated_at'      => 'DATE NULL',
        'deactivation_note'   => 'TEXT NULL',
        'birth_date'  => 'DATE NULL',
        'breed'       => 'VARCHAR(150) NULL',
        'color'       => 'VARCHAR(100) NULL',
        'chip_number' => 'VARCHAR(50) NULL',
        'lab_number'  => 'VARCHAR(50) NULL',
        'weight'      => 'DECIMAL(6,2) NULL',
    ];
    foreach ($add as $c => $type) {
        if (!in_array($c, $cols, true)) $db->exec("ALTER TABLE animals ADD COLUMN `$c` $type");
    }

    $db->exec("CREATE TABLE IF NOT EXISTS vaccination_types (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        task_group VARCHAR(30) DEFAULT 'vaccination',
        is_primary TINYINT(1) NULL,
        default_interval_days INT NULL,
        sort_order INT DEFAULT 0,
        is_active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT NOW(),
        UNIQUE KEY uniq_name (name),
        KEY idx_sort (sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $db->exec("CREATE TABLE IF NOT EXISTS vaccinations (
        id VARCHAR(36) PRIMARY KEY,
        animal_id VARCHAR(36) NOT NULL,
        type_id VARCHAR(36) NULL,
        vaccine_name VARCHAR(255) NOT NULL,
        doses DECIMAL(5,2) DEFAULT 1,
        done_date DATE NOT NULL,
        next_date DATE NULL,
        age_text VARCHAR(60) NULL,
        note TEXT NULL,
        procedure_id VARCHAR(36) NULL,
        created_by VARCHAR(36) NULL,
        created_at DATETIME DEFAULT NOW(),
        KEY idx_animal (animal_id),
        KEY idx_next (next_date),
        KEY idx_done (done_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    if ((int)$db->query("SELECT COUNT(*) FROM vaccination_types")->fetchColumn() === 0) {
        // Стартовый набор из ТЗ 8.2, порядок как в таблице документа.
        $seed = [
            ['Вакцинация от бешенства первичная',        'vaccination', 1, 21],
            ['Вакцинация от бешенства ревакцинация',     'vaccination', 0, 365],
            ['Вакцинация от вирусов кошки первичная',    'vaccination', 1, 21],
            ['Вакцинация от вирусов кошки ревакцинация', 'vaccination', 0, 365],
            ['Вакцинация от вирусов собаки первичная',   'vaccination', 1, 21],
            ['Вакцинация от вирусов собаки ревакцинация','vaccination', 0, 365],
            ['Обработка — Блохи',                        'treatment',   null, 30],
            ['Обработка — Глисты',                       'treatment',   null, 90],
        ];
        $ins = $db->prepare("INSERT INTO vaccination_types (id,name,task_group,is_primary,default_interval_days,sort_order) VALUES (?,?,?,?,?,?)");
        $i = 10;
        foreach ($seed as $s) { $ins->execute([bin2hex(random_bytes(16)), $s[0], $s[1], $s[2], $s[3], $i]); $i += 10; }
    }
}

// Возраст на дату — для колонки «Возраст» в истории вакцинаций.
// Если даты рождения нет (а у приютских её обычно нет), возвращаем null,
// а не выдуманное значение.
function ageOnDate(?string $birth, string $onDate): ?string {
    if (!$birth) return null;
    try { $b = new DateTime($birth); $d = new DateTime($onDate); } catch (Exception $e) { return null; }
    if ($b > $d) return null;
    $diff = $b->diff($d);
    if ($diff->y > 0)  return $diff->y . ' г. ' . ($diff->m ? $diff->m . ' мес.' : '');
    if ($diff->m > 0)  return $diff->m . ' мес.' . ($diff->d ? ' ' . $diff->d . ' дн.' : '');
    if ($diff->days >= 7) return intdiv($diff->days, 7) . ' нед.';
    return $diff->days . ' дн.';
}

function diagnosesHandler(string $method, ?string $id): void {
    $db = db();
    ensureMedTables($db);

    if ($method === 'GET') {
        // Счётчик использований нужен, чтобы в справочнике было видно,
        // какие диагнозы реально встречаются, а какие занесены «на будущее».
        ok($db->query("SELECT d.*, (SELECT COUNT(*) FROM treatments t WHERE t.diagnosis_id=d.id) AS usage_count
                       FROM diagnoses d WHERE d.is_active=1 ORDER BY d.sort_order, d.name")->fetchAll());
    }
    if ($method === 'POST') {
        $b = body();
        if (empty(trim($b['name'] ?? ''))) err('Не указано название диагноза');
        $newId = bin2hex(random_bytes(16));
        $max = (int)$db->query("SELECT COALESCE(MAX(sort_order),0) FROM diagnoses")->fetchColumn();
        $db->prepare("INSERT INTO diagnoses (id,name,outcome,category,sort_order)
                      VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE is_active=1")
           ->execute([$newId, trim($b['name']), $b['outcome'] ?: null,
                      $b['category'] ?: null, $b['sort_order'] ?? $max + 10]);
        logAudit($db, 'other', 'Справочник диагнозов: добавлен «' . trim($b['name']) . '»', $newId, trim($b['name']), 'diagnosis');
        ok(['id' => $newId], 201);
    }
    if ($method === 'PUT' && $id) {
        $b = body(); $set = []; $params = [];
        foreach (['name','outcome','category','sort_order'] as $c) {
            if (array_key_exists($c, $b)) { $set[] = "`$c`=?"; $params[] = $b[$c] === '' ? null : $b[$c]; }
        }
        if (!$set) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE diagnoses SET " . implode(',', $set) . " WHERE id=?")->execute($params);
        ok(['updated' => true]);
    }
    if ($method === 'DELETE' && $id) {
        $c = $db->prepare("SELECT COUNT(*) FROM treatments WHERE diagnosis_id=?");
        $c->execute([$id]);
        if ((int)$c->fetchColumn() > 0) {
            // Диагноз уже стоит в истории лечения — скрываем, не удаляем.
            $db->prepare("UPDATE diagnoses SET is_active=0 WHERE id=?")->execute([$id]);
            ok(['hidden' => true]);
        }
        $db->prepare("DELETE FROM diagnoses WHERE id=?")->execute([$id]);
        ok(['deleted' => true]);
    }
    err('Method not allowed', 405);
}

function vaccTypesHandler(string $method, ?string $id): void {
    $db = db();
    ensureVaccinationTables($db);

    if ($method === 'GET') {
        ok($db->query("SELECT * FROM vaccination_types WHERE is_active=1 ORDER BY sort_order, name")->fetchAll());
    }
    if ($method === 'POST') {
        $b = body();
        if (empty($b['name'])) err('Не указано название типа');
        $newId = bin2hex(random_bytes(16));
        $max = (int)$db->query("SELECT COALESCE(MAX(sort_order),0) FROM vaccination_types")->fetchColumn();
        $db->prepare("INSERT INTO vaccination_types (id,name,task_group,is_primary,default_interval_days,sort_order)
                      VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE is_active=1")
           ->execute([$newId, trim($b['name']), $b['task_group'] ?? 'vaccination',
                      isset($b['is_primary']) ? (int)$b['is_primary'] : null,
                      $b['default_interval_days'] ?: null, $b['sort_order'] ?? $max + 10]);
        logAudit($db, 'other', 'Справочник вакцинаций: добавлен тип «' . $b['name'] . '»', $newId, $b['name'], 'vacc_type');
        ok(['id' => $newId], 201);
    }
    if ($method === 'PUT' && $id) {
        $b = body(); $set = []; $params = [];
        foreach (['name','task_group','is_primary','default_interval_days','sort_order'] as $c) {
            if (array_key_exists($c, $b)) { $set[] = "`$c`=?"; $params[] = $b[$c] === '' ? null : $b[$c]; }
        }
        if (!$set) err('Nothing to update');
        $params[] = $id;
        $db->prepare("UPDATE vaccination_types SET " . implode(',', $set) . " WHERE id=?")->execute($params);
        ok(['updated' => true]);
    }
    if ($method === 'DELETE' && $id) {
        $c = $db->prepare("SELECT COUNT(*) FROM vaccinations WHERE type_id=?");
        $c->execute([$id]);
        if ((int)$c->fetchColumn() > 0) {
            // Тип использован в истории — скрываем, но не удаляем,
            // иначе прошлые записи потеряют название типа.
            $db->prepare("UPDATE vaccination_types SET is_active=0 WHERE id=?")->execute([$id]);
            ok(['hidden' => true]);
        }
        $db->prepare("DELETE FROM vaccination_types WHERE id=?")->execute([$id]);
        ok(['deleted' => true]);
    }
    err('Method not allowed', 405);
}

function vaccinationsHandler(string $method, ?string $id): void {
    $db = db();
    ensureVaccinationTables($db);

    if ($method === 'GET') {
        if (!$id) err('Не указано животное', 400);
        $a = $db->prepare("SELECT birth_date FROM animals WHERE id=?");
        $a->execute([$id]);
        $birth = $a->fetchColumn() ?: null;

        $stmt = $db->prepare("SELECT v.*, t.name AS type_name, t.task_group, u.name AS user_name
                              FROM vaccinations v
                              LEFT JOIN vaccination_types t ON v.type_id=t.id
                              LEFT JOIN users u ON v.created_by=u.id
                              WHERE v.animal_id=? ORDER BY v.done_date DESC, v.created_at DESC");
        $stmt->execute([$id]);
        $rows = $stmt->fetchAll();
        // Возраст считаем на лету: дата рождения могла появиться позже записи.
        foreach ($rows as &$r) $r['age_text'] = ageOnDate($birth, $r['done_date']);
        ok(['items' => $rows, 'birth_date' => $birth]);
    }

    if ($method === 'POST') {
        $b = body();
        $animalId = $b['animal_id'] ?? null;
        if (!$animalId) err('Не указано животное');
        if (empty($b['vaccine_name'])) err('Не указана вакцина');

        $doneDate = $b['done_date'] ?? date('Y-m-d');
        $nextDate = $b['next_date'] ?: null;

        // «Удалить предыдущие даты повторов» — снимаем ранее запланированные
        // повторы этой же вакцины, чтобы не задваивать задачи.
        $removed = 0;
        if (!empty($b['clear_previous'])) {
            $old = $db->prepare("SELECT procedure_id FROM vaccinations
                                 WHERE animal_id=? AND vaccine_name=? AND procedure_id IS NOT NULL AND id<>''");
            $old->execute([$animalId, $b['vaccine_name']]);
            foreach ($old->fetchAll(PDO::FETCH_COLUMN) as $pid) {
                if (!$pid) continue;
                $db->prepare("DELETE FROM tasks WHERE procedure_id=? AND is_completed=0 AND date > CURDATE()")->execute([$pid]);
                $db->prepare("DELETE FROM procedures WHERE id=?")->execute([$pid]);
                $removed++;
            }
            $db->prepare("UPDATE vaccinations SET next_date=NULL, procedure_id=NULL
                          WHERE animal_id=? AND vaccine_name=?")->execute([$animalId, $b['vaccine_name']]);
        }

        // Повтор превращаем в обычное назначение на один день: тогда он сам
        // попадёт в задачник, отметку, историю и отчёты — вместо отдельного
        // механизма напоминаний рядом с работающим.
        $procId = null;
        if ($nextDate) {
            $type = null;
            if (!empty($b['type_id'])) {
                $t = $db->prepare("SELECT * FROM vaccination_types WHERE id=?");
                $t->execute([$b['type_id']]);
                $type = $t->fetch() ?: null;
            }
            $group = $type['task_group'] ?? 'vaccination';
            $procId = bin2hex(random_bytes(16));
            $db->prepare("INSERT INTO procedures (id,animal_id,medication_name,dosage,`group`,period_type,frequency,
                          start_date,course_end_date,course_end_type,time_slots,doctor_name,notes)
                          VALUES (?,?,?,?,?,'daily',1,?,?,'endDate',?,?,?)")
               ->execute([$procId, $animalId, $b['vaccine_name'], ($b['doses'] ?? 1) . ' доз.', $group,
                          $nextDate, $nextDate, json_encode(['slot_11_12']),
                          $b['doctor_name'] ?? (currentUser()['name'] ?? null),
                          'Повтор: ' . ($type['name'] ?? 'вакцинация')]);
            generateTasksForProcedure($db, $procId, [
                'animal_id' => $animalId, 'period_type' => 'daily',
                'start_date' => $nextDate, 'course_end_date' => $nextDate,
                'time_slots' => ['slot_11_12'],
            ]);
        }

        $newId = bin2hex(random_bytes(16));
        $db->prepare("INSERT INTO vaccinations (id,animal_id,type_id,vaccine_name,doses,done_date,next_date,note,procedure_id,created_by)
                      VALUES (?,?,?,?,?,?,?,?,?,?)")
           ->execute([$newId, $animalId, $b['type_id'] ?: null, $b['vaccine_name'],
                      $b['doses'] ?? 1, $doneDate, $nextDate, $b['note'] ?: null, $procId,
                      currentUser()['id'] ?? null]);

        $an = $db->prepare("SELECT name FROM animals WHERE id=?"); $an->execute([$animalId]);
        logAudit($db, 'other', 'Вакцинация: ' . (string)$an->fetchColumn() . ' — ' . $b['vaccine_name']
                 . ($nextDate ? ', повтор ' . $nextDate : ''), $animalId, $b['vaccine_name'], 'vaccination');

        ok(['id' => $newId, 'procedure_id' => $procId, 'cleared_previous' => $removed], 201);
    }

    if ($method === 'DELETE' && $id) {
        $v = $db->prepare("SELECT procedure_id FROM vaccinations WHERE id=?");
        $v->execute([$id]);
        $pid = $v->fetchColumn();
        if ($pid) {
            $db->prepare("DELETE FROM tasks WHERE procedure_id=? AND is_completed=0 AND date > CURDATE()")->execute([$pid]);
            $db->prepare("DELETE FROM procedures WHERE id=?")->execute([$pid]);
        }
        $db->prepare("DELETE FROM vaccinations WHERE id=?")->execute([$id]);
        ok(['deleted' => true]);
    }

    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// МЕДИЦИНА: ХВИ-тесты, стерилизации, донорство
// ══════════════════════════════════════════════════════════════
function ensureMedTables(PDO $db): void {
    static $done = false;
    if ($done) return;
    $done = true;

    $db->exec("CREATE TABLE IF NOT EXISTS hvi_tests (
        id VARCHAR(36) PRIMARY KEY,
        animal_id VARCHAR(36) NOT NULL,
        test_date DATE NOT NULL,
        test_type VARCHAR(30) NOT NULL,
        result VARCHAR(20) NOT NULL,
        doctor_name VARCHAR(150) NULL,
        note TEXT NULL,
        created_by VARCHAR(36) NULL,
        created_at DATETIME DEFAULT NOW(),
        KEY idx_animal (animal_id), KEY idx_date (test_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Данные из «Учет животных 2026»: метод анализа, стадия лейкемии и стоимость.
    // Один забор крови = до 4 записей (ПЦР/ИХА × FIV/FeLV), поэтому стоимость
    // проставляется только первой записи забора — иначе сумма затрат учетверится.
    if ($db->query("SHOW TABLES LIKE 'treatments'")->fetchColumn()) {
        $tc = $db->query("SHOW COLUMNS FROM treatments")->fetchAll(PDO::FETCH_COLUMN);
        if (!in_array('age_text', $tc, true)) $db->exec("ALTER TABLE treatments ADD COLUMN age_text VARCHAR(40) NULL");
    }

    $hc = $db->query("SHOW COLUMNS FROM hvi_tests")->fetchAll(PDO::FETCH_COLUMN);
    foreach ([
        'method' => "VARCHAR(20) NULL",
        'stage'  => "VARCHAR(40) NULL",
        'cost'   => "DECIMAL(10,2) NULL",
        'source' => "VARCHAR(40) NULL",
    ] as $c => $type) {
        if (!in_array($c, $hc, true)) $db->exec("ALTER TABLE hvi_tests ADD COLUMN `$c` $type");
    }

    $db->exec("CREATE TABLE IF NOT EXISTS diagnoses (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        outcome VARCHAR(60) NULL,
        category VARCHAR(60) NULL,
        is_active TINYINT(1) DEFAULT 1,
        sort_order INT DEFAULT 0,
        created_at DATETIME DEFAULT NOW(),
        UNIQUE KEY uniq_name (name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $db->exec("CREATE TABLE IF NOT EXISTS treatments (
        id VARCHAR(36) PRIMARY KEY,
        animal_id VARCHAR(36) NOT NULL,
        start_date DATE NOT NULL,
        diagnosis_id VARCHAR(36) NULL,
        diagnosis_text VARCHAR(200) NULL,
        outcome VARCHAR(120) NULL,        -- заполняется свободным текстом, не словарь
        category VARCHAR(60) NULL,
        age_text VARCHAR(40) NULL,        -- возраст на момент лечения, как записан в журнале
        note TEXT NULL,
        source VARCHAR(40) NULL,
        created_by VARCHAR(36) NULL,
        created_at DATETIME DEFAULT NOW(),
        KEY idx_animal (animal_id), KEY idx_date (start_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // У одного случая лечения бывает несколько диагнозов сразу
    // («Перелом бедра, Перелом таза»). Без связки статистика по диагнозам
    // считала бы такой случай как один составной диагноз и занижала бы каждый.
    $db->exec("CREATE TABLE IF NOT EXISTS treatment_diagnoses (
        treatment_id VARCHAR(36) NOT NULL,
        diagnosis_id VARCHAR(36) NOT NULL,
        is_primary TINYINT(1) DEFAULT 0,
        PRIMARY KEY (treatment_id, diagnosis_id),
        KEY idx_diag (diagnosis_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $db->exec("CREATE TABLE IF NOT EXISTS sterilizations (
        id VARCHAR(36) PRIMARY KEY,
        animal_id VARCHAR(36) NOT NULL,
        done_date DATE NOT NULL,
        kind VARCHAR(30) DEFAULT 'sterilization',
        doctor_name VARCHAR(150) NULL,
        clinic VARCHAR(150) NULL,
        complications TEXT NULL,
        note TEXT NULL,
        created_by VARCHAR(36) NULL,
        created_at DATETIME DEFAULT NOW(),
        KEY idx_animal (animal_id), KEY idx_date (done_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $db->exec("CREATE TABLE IF NOT EXISTS blood_donations (
        id VARCHAR(36) PRIMARY KEY,
        donor_id VARCHAR(36) NOT NULL,
        recipient_id VARCHAR(36) NULL,
        donation_date DATE NOT NULL,
        volume_ml INT NULL,
        doctor_name VARCHAR(150) NULL,
        note TEXT NULL,
        created_by VARCHAR(36) NULL,
        created_at DATETIME DEFAULT NOW(),
        KEY idx_donor (donor_id), KEY idx_date (donation_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

// Результат теста сразу проставляется в карточку животного: колонки
// hiv_status и leukemia_status в базе есть, но их никто не заполнял —
// теперь они наполняются из фактических тестов, а не руками.
function syncTestStatus(PDO $db, string $animalId): void {
    foreach (['fiv' => 'hiv_status', 'felv' => 'leukemia_status'] as $type => $col) {
        // ПЦР провирусной ДНК — подтверждающий анализ, ИХА-экспресс — скрининговый.
        // При совпадении дат статус берём по ПЦР, иначе экспресс-тест может
        // перебить более достоверный результат.
        $s = $db->prepare("SELECT result FROM hvi_tests WHERE animal_id=? AND test_type=?
                           ORDER BY test_date DESC, (method='pcr') DESC, created_at DESC LIMIT 1");
        $s->execute([$animalId, $type]);
        $r = $s->fetchColumn();
        if ($r === false) continue;
        $val = $r === 'positive' ? 'положительный' : ($r === 'negative' ? 'отрицательный' : 'сомнительный');
        $db->prepare("UPDATE animals SET `$col`=? WHERE id=?")->execute([$val, $animalId]);
    }
}

function hviHandler(string $method, ?string $id): void {
    $db = db(); ensureMedTables($db);

    if ($method === 'GET') {
        if (!$id) err('Не указано животное', 400);
        $s = $db->prepare("SELECT t.*, u.name AS user_name FROM hvi_tests t
                           LEFT JOIN users u ON t.created_by=u.id
                           WHERE t.animal_id=? ORDER BY t.test_date DESC, t.created_at DESC");
        $s->execute([$id]);
        ok($s->fetchAll());
    }
    if ($method === 'POST') {
        $b = body();
        if (empty($b['animal_id']) || empty($b['test_type']) || empty($b['result'])) err('Не хватает данных теста');
        if (!in_array($b['result'], ['positive','negative','invalid'], true)) err('Неизвестный результат');
        $newId = bin2hex(random_bytes(16));
        $db->prepare("INSERT INTO hvi_tests (id,animal_id,test_date,test_type,result,doctor_name,note,created_by)
                      VALUES (?,?,?,?,?,?,?,?)")
           ->execute([$newId, $b['animal_id'], $b['test_date'] ?? date('Y-m-d'), $b['test_type'],
                      $b['result'], $b['doctor_name'] ?: null, $b['note'] ?: null, currentUser()['id'] ?? null]);
        syncTestStatus($db, $b['animal_id']);
        $an = $db->prepare("SELECT name FROM animals WHERE id=?"); $an->execute([$b['animal_id']]);
        logAudit($db, 'other', 'Тест ' . $b['test_type'] . ': ' . (string)$an->fetchColumn() . ' — ' . $b['result'],
                 $b['animal_id'], null, 'hvi');
        ok(['id' => $newId], 201);
    }
    if ($method === 'DELETE' && $id) {
        $a = $db->prepare("SELECT animal_id FROM hvi_tests WHERE id=?"); $a->execute([$id]);
        $aid = $a->fetchColumn();
        $db->prepare("DELETE FROM hvi_tests WHERE id=?")->execute([$id]);
        if ($aid) syncTestStatus($db, $aid);
        ok(['deleted' => true]);
    }
    err('Method not allowed', 405);
}

function sterilHandler(string $method, ?string $id): void {
    $db = db(); ensureMedTables($db);

    if ($method === 'GET') {
        // Отчёт за период — по видам, полу и хирургам (ТЗ v3.0 §7.5).
        if (($_GET['view'] ?? '') === 'report') {
            $from = $_GET['from'] ?? date('Y-01-01');
            $to   = $_GET['to']   ?? date('Y-m-d');
            $q = function ($sql) use ($db, $from, $to) {
                $s = $db->prepare($sql); $s->execute([$from, $to]); return $s->fetchAll();
            };
            ok(['period' => ['from' => $from, 'to' => $to],
                'total' => (int)($q("SELECT COUNT(*) c FROM sterilizations WHERE done_date BETWEEN ? AND ?")[0]['c'] ?? 0),
                'by_species' => $q("SELECT a.species, a.gender, COUNT(*) AS cnt
                                    FROM sterilizations s JOIN animals a ON s.animal_id=a.id
                                    WHERE s.done_date BETWEEN ? AND ? GROUP BY a.species, a.gender"),
                'by_doctor'  => $q("SELECT COALESCE(NULLIF(TRIM(doctor_name),''),'не указан') AS doctor, COUNT(*) AS cnt
                                    FROM sterilizations WHERE done_date BETWEEN ? AND ? GROUP BY doctor ORDER BY cnt DESC"),
                'by_month'   => $q("SELECT DATE_FORMAT(done_date,'%Y-%m') AS month, COUNT(*) AS cnt
                                    FROM sterilizations WHERE done_date BETWEEN ? AND ? GROUP BY month ORDER BY month")]);
        }
        if (!$id) err('Не указано животное', 400);
        $s = $db->prepare("SELECT s.*, u.name AS user_name FROM sterilizations s
                           LEFT JOIN users u ON s.created_by=u.id
                           WHERE s.animal_id=? ORDER BY s.done_date DESC");
        $s->execute([$id]);
        ok($s->fetchAll());
    }
    if ($method === 'POST') {
        $b = body();
        if (empty($b['animal_id'])) err('Не указано животное');
        $newId = bin2hex(random_bytes(16));
        $db->prepare("INSERT INTO sterilizations (id,animal_id,done_date,kind,doctor_name,clinic,complications,note,created_by)
                      VALUES (?,?,?,?,?,?,?,?,?)")
           ->execute([$newId, $b['animal_id'], $b['done_date'] ?? date('Y-m-d'),
                      $b['kind'] ?? 'sterilization', $b['doctor_name'] ?: null, $b['clinic'] ?: null,
                      $b['complications'] ?: null, $b['note'] ?: null, currentUser()['id'] ?? null]);
        $an = $db->prepare("SELECT name FROM animals WHERE id=?"); $an->execute([$b['animal_id']]);
        logAudit($db, 'other', 'Стерилизация: ' . (string)$an->fetchColumn(), $b['animal_id'], null, 'sterilization');
        ok(['id' => $newId], 201);
    }
    if ($method === 'DELETE' && $id) {
        $db->prepare("DELETE FROM sterilizations WHERE id=?")->execute([$id]);
        ok(['deleted' => true]);
    }
    err('Method not allowed', 405);
}

function donationsHandler(string $method, ?string $id): void {
    $db = db(); ensureMedTables($db); ensureVaccinationTables($db);

    if ($method === 'GET') {
        // Подбор доноров по критериям из ТЗ. Финальное решение всё равно
        // за врачом — система только сужает список.
        if (($_GET['view'] ?? '') === 'candidates') {
            $species = $_GET['species'] ?? null;
            $where = ['a.is_active=1'];
            $params = [];
            if ($species) { $where[] = 'a.species=?'; $params[] = $species; }

            $sql = "SELECT a.id, a.name, a.species, a.gender, a.birth_date, a.blood_type,
                           r.name AS route_name,
                           TIMESTAMPDIFF(YEAR, a.birth_date, CURDATE()) AS age_years,
                           (SELECT MAX(d.donation_date) FROM blood_donations d WHERE d.donor_id=a.id) AS last_donation,
                           (SELECT MAX(s.done_date) FROM sterilizations s WHERE s.animal_id=a.id) AS sterilized_at,
                           (SELECT t.result FROM hvi_tests t WHERE t.animal_id=a.id AND t.test_type='fiv'
                            ORDER BY t.test_date DESC LIMIT 1) AS fiv,
                           (SELECT t.result FROM hvi_tests t WHERE t.animal_id=a.id AND t.test_type='felv'
                            ORDER BY t.test_date DESC LIMIT 1) AS felv
                    FROM animals a LEFT JOIN routes r ON a.route_id=r.id
                    WHERE " . implode(' AND ', $where) . " ORDER BY a.name";
            $st = $db->prepare($sql);
            $st->execute($params);
            $rows = $st->fetchAll();

            $today = new DateTime();
            $out = [];
            foreach ($rows as $a) {
                $block = [];   // что мешает быть донором прямо сейчас
                if ($a['birth_date'] === null)              $block[] = 'не указана дата рождения';
                elseif ($a['age_years'] < 1)                $block[] = 'младше года';
                elseif ($a['age_years'] > 7)                $block[] = 'старше 7 лет';

                if ($a['fiv'] === null || $a['felv'] === null) $block[] = 'нет тестов на ХВИ';
                elseif ($a['fiv'] === 'positive' || $a['felv'] === 'positive') $block[] = 'положительный тест';

                if (!$a['sterilized_at']) $block[] = 'нет отметки о стерилизации';
                else {
                    $d = (new DateTime($a['sterilized_at']))->diff($today)->days;
                    if ($d < 45) $block[] = "после стерилизации прошло $d дн. (нужно 45)";
                }
                if ($a['last_donation']) {
                    $d = (new DateTime($a['last_donation']))->diff($today)->days;
                    if ($d < 90) $block[] = "с последней донации $d дн. (нужно 90)";
                }
                $a['blockers'] = $block;
                $a['eligible'] = empty($block);
                $out[] = $a;
            }
            usort($out, fn($x, $y) => [$y['eligible'], -count($x['blockers'])] <=> [$x['eligible'], -count($y['blockers'])]);
            ok(['criteria' => 'возраст 1–7 лет · отрицательные тесты ХВИ и лейкемии · стерилизация более 45 дней назад · с последней донации более 90 дней',
                'items' => $out]);
        }

        if (!$id) err('Не указано животное', 400);
        $s = $db->prepare("SELECT d.*, rec.name AS recipient_name, u.name AS user_name
                           FROM blood_donations d
                           LEFT JOIN animals rec ON d.recipient_id=rec.id
                           LEFT JOIN users u ON d.created_by=u.id
                           WHERE d.donor_id=? ORDER BY d.donation_date DESC");
        $s->execute([$id]);
        ok($s->fetchAll());
    }

    if ($method === 'POST') {
        $b = body();
        if (empty($b['donor_id'])) err('Не указан донор');
        $newId = bin2hex(random_bytes(16));
        $db->prepare("INSERT INTO blood_donations (id,donor_id,recipient_id,donation_date,volume_ml,doctor_name,note,created_by)
                      VALUES (?,?,?,?,?,?,?,?)")
           ->execute([$newId, $b['donor_id'], $b['recipient_id'] ?: null, $b['donation_date'] ?? date('Y-m-d'),
                      $b['volume_ml'] ?: null, $b['doctor_name'] ?: null, $b['note'] ?: null, currentUser()['id'] ?? null]);
        $an = $db->prepare("SELECT name FROM animals WHERE id=?"); $an->execute([$b['donor_id']]);
        logAudit($db, 'other', 'Донация крови: ' . (string)$an->fetchColumn(), $b['donor_id'], null, 'donation');
        ok(['id' => $newId], 201);
    }
    if ($method === 'DELETE' && $id) {
        $db->prepare("DELETE FROM blood_donations WHERE id=?")->execute([$id]);
        ok(['deleted' => true]);
    }
    err('Method not allowed', 405);
}

// ══════════════════════════════════════════════════════════════
// ОТЧЁТ ПО ВЫБЫТИЮ ЖИВОТНЫХ
// ══════════════════════════════════════════════════════════════
function outcomeReportHandler(): void {
    $db = db();
    ensureVaccinationTables($db);

    $from = $_GET['from'] ?? date('Y-01-01');
    $to   = $_GET['to']   ?? date('Y-m-d');

    $stmt = $db->prepare("SELECT COALESCE(deactivation_reason,'не указана') AS reason,
                                 COUNT(*) AS cnt,
                                 SUM(species='cat') AS cats, SUM(species='dog') AS dogs
                          FROM animals
                          WHERE is_active=0 AND deactivated_at BETWEEN ? AND ?
                          GROUP BY reason ORDER BY cnt DESC");
    $stmt->execute([$from, $to]);
    $byReason = $stmt->fetchAll();

    $m = $db->prepare("SELECT DATE_FORMAT(deactivated_at,'%Y-%m') AS month,
                              COALESCE(deactivation_reason,'не указана') AS reason, COUNT(*) AS cnt
                       FROM animals WHERE is_active=0 AND deactivated_at BETWEEN ? AND ?
                       GROUP BY month, reason ORDER BY month");
    $m->execute([$from, $to]);

    // Историческая масса: выбывшие до того, как причину начали фиксировать.
    $noDate = (int)$db->query("SELECT COUNT(*) FROM animals WHERE is_active=0 AND deactivated_at IS NULL")->fetchColumn();

    ok(['period' => ['from' => $from, 'to' => $to],
        'by_reason' => $byReason, 'by_month' => $m->fetchAll(),
        'without_date' => $noDate]);
}

// ══════════════════════════════════════════════════════════════
// ОТЧЁТЫ ПО ВАКЦИНАЦИЯМ (ТЗ v3.0 §7.1–7.2)
// ══════════════════════════════════════════════════════════════
// Ключевое требование главврача: считать не только дозы (для СББЖ и
// бухгалтерии), но и УНИКАЛЬНЫХ животных. «50 собак и 102 кошки
// провакцинировано в марте (при этом использовано 400 доз)».
function vaccReportHandler(): void {
    $db = db();
    ensureVaccinationTables($db);

    $from = $_GET['from'] ?? date('Y-m-01');
    $to   = $_GET['to']   ?? date('Y-m-d');
    $p    = [$from, $to];

    $base = "FROM vaccinations v
             JOIN animals a ON v.animal_id = a.id
             LEFT JOIN vaccination_types t ON v.type_id = t.id
             WHERE v.done_date BETWEEN ? AND ?";

    $q = function (string $sql) use ($db, $p) {
        $s = $db->prepare($sql); $s->execute($p); return $s;
    };

    $res = [];
    $res['period'] = ['from' => $from, 'to' => $to];

    // Вакцинации и обработки считаем раздельно — это разные вещи и разные отчёты.
    foreach (['vaccination' => 'вакцинации', 'treatment' => 'обработки'] as $grp => $label) {
        $cond = " AND COALESCE(t.task_group,'vaccination') = '" . $grp . "'";

        $tot = $q("SELECT COUNT(DISTINCT v.animal_id) AS animals, COUNT(*) AS records, COALESCE(SUM(v.doses),0) AS doses $base $cond")->fetch();

        $bySpecies = $q("SELECT a.species, COUNT(DISTINCT v.animal_id) AS animals, COALESCE(SUM(v.doses),0) AS doses
                         $base $cond GROUP BY a.species ORDER BY animals DESC")->fetchAll();

        // Первичная или повторная — признак берём из типа.
        $byPrimary = $q("SELECT CASE WHEN t.is_primary=1 THEN 'primary'
                                     WHEN t.is_primary=0 THEN 'repeat' ELSE 'unknown' END AS kind,
                                COUNT(DISTINCT v.animal_id) AS animals, COUNT(*) AS records, COALESCE(SUM(v.doses),0) AS doses
                         $base $cond GROUP BY kind")->fetchAll();

        $byType = $q("SELECT COALESCE(t.name,'без типа') AS name,
                             COUNT(DISTINCT v.animal_id) AS animals, COUNT(*) AS records, COALESCE(SUM(v.doses),0) AS doses
                      $base $cond GROUP BY t.id, t.name ORDER BY records DESC")->fetchAll();

        $byVaccine = $q("SELECT v.vaccine_name AS name, COUNT(DISTINCT v.animal_id) AS animals,
                                COUNT(*) AS records, COALESCE(SUM(v.doses),0) AS doses
                         $base $cond GROUP BY v.vaccine_name ORDER BY doses DESC LIMIT 30")->fetchAll();

        $res[$grp] = [
            'label'       => $label,
            'animals'     => (int)$tot['animals'],
            'records'     => (int)$tot['records'],
            'doses'       => (float)$tot['doses'],
            'by_species'  => $bySpecies,
            'by_primary'  => $byPrimary,
            'by_type'     => $byType,
            'by_vaccine'  => $byVaccine,
        ];
    }

    // Просроченные повторы — по всем активным животным, независимо от периода.
    $over = $db->query("SELECT v.id, v.animal_id, a.name AS animal_name, a.species, r.name AS route_name,
                               v.vaccine_name, v.next_date, COALESCE(t.name,'') AS type_name,
                               DATEDIFF(CURDATE(), v.next_date) AS days_late
                        FROM vaccinations v
                        JOIN animals a ON v.animal_id=a.id AND a.is_active=1
                        LEFT JOIN routes r ON a.route_id=r.id
                        LEFT JOIN vaccination_types t ON v.type_id=t.id
                        WHERE v.next_date IS NOT NULL AND v.next_date < CURDATE()
                          AND NOT EXISTS (SELECT 1 FROM tasks tk
                                          WHERE tk.procedure_id = v.procedure_id AND tk.is_completed = 1)
                        ORDER BY v.next_date LIMIT 200")->fetchAll();
    $res['overdue'] = $over;

    // Ближайшие — чтобы planировать, а не только догонять просроченное.
    $soon = $db->query("SELECT v.animal_id, a.name AS animal_name, r.name AS route_name,
                               v.vaccine_name, v.next_date, COALESCE(t.name,'') AS type_name,
                               DATEDIFF(v.next_date, CURDATE()) AS days_left
                        FROM vaccinations v
                        JOIN animals a ON v.animal_id=a.id AND a.is_active=1
                        LEFT JOIN routes r ON a.route_id=r.id
                        LEFT JOIN vaccination_types t ON v.type_id=t.id
                        WHERE v.next_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)
                        ORDER BY v.next_date LIMIT 200")->fetchAll();
    $res['upcoming'] = $soon;

    ok($res);
}

// ══════════════════════════════════════════════════════════════
// ЭКСПОРТ CSV
// ══════════════════════════════════════════════════════════════
function exportHandler(): void {
    $db   = db();
    $type = $_GET['type'] ?? '';

    switch ($type) {
        case 'animals':
            $rows = $db->query("SELECT a.name AS 'Кличка', a.species AS 'Вид', a.gender AS 'Пол',
                       r.name AS 'Маршрут', a.room AS 'Комната', a.cage_number AS 'Бокс',
                       a.status AS 'Состояние', a.allergies AS 'Аллергии', a.notes AS 'Заметки'
                FROM animals a LEFT JOIN routes r ON a.route_id=r.id
                WHERE a.is_active=1 ORDER BY a.name")->fetchAll();
            $name = 'zhivotnye';
            break;

        case 'procedures':
            $rows = $db->query("SELECT a.name AS 'Животное', r.name AS 'Маршрут', p.medication_name AS 'Препарат',
                       p.dosage AS 'Доза', p.`group` AS 'Группа', p.administration_route AS 'Путь введения',
                       p.start_date AS 'Начало', p.course_end_date AS 'Окончание', p.doctor_name AS 'Врач', p.notes AS 'Заметки'
                FROM procedures p JOIN animals a ON p.animal_id=a.id LEFT JOIN routes r ON a.route_id=r.id
                ORDER BY a.name, p.medication_name")->fetchAll();
            $name = 'naznacheniya';
            break;

        case 'tasks':
            $date = $_GET['date'] ?? date('Y-m-d');
            $stmt = $db->prepare("SELECT t.date AS 'Дата', t.time_of_day AS 'Время', a.name AS 'Животное',
                       r.name AS 'Маршрут', a.room AS 'Комната', p.medication_name AS 'Препарат', p.dosage AS 'Доза',
                       CASE WHEN t.is_completed=1 THEN 'да' ELSE 'нет' END AS 'Выполнено',
                       u.name AS 'Исполнитель', t.completed_at AS 'Время выполнения'
                FROM tasks t JOIN procedures p ON t.procedure_id=p.id JOIN animals a ON t.animal_id=a.id
                LEFT JOIN routes r ON a.route_id=r.id LEFT JOIN users u ON t.completed_by=u.id
                WHERE t.date=? ORDER BY t.time_of_day, a.name");
            $stmt->execute([$date]);
            $rows = $stmt->fetchAll();
            $name = 'zadachi_' . $date;
            break;

        case 'tasks_period':
            $from = $_GET['from'] ?? date('Y-m-d');
            $to   = $_GET['to']   ?? date('Y-m-d');
            $stmt = $db->prepare("SELECT t.date AS 'Дата', t.time_of_day AS 'Время', a.name AS 'Животное',
                       r.name AS 'Маршрут', p.medication_name AS 'Препарат', p.dosage AS 'Доза',
                       CASE WHEN t.is_completed=1 THEN 'да' ELSE 'нет' END AS 'Выполнено',
                       u.name AS 'Исполнитель', t.completed_at AS 'Время выполнения'
                FROM tasks t JOIN procedures p ON t.procedure_id=p.id JOIN animals a ON t.animal_id=a.id
                LEFT JOIN routes r ON a.route_id=r.id LEFT JOIN users u ON t.completed_by=u.id
                WHERE t.date BETWEEN ? AND ? ORDER BY t.date, t.time_of_day, a.name");
            $stmt->execute([$from, $to]);
            $rows = $stmt->fetchAll();
            $name = 'zadachi_' . $from . '_' . $to;
            break;

        case 'history':
            $from = $_GET['from'] ?? date('Y-m-d', strtotime('-30 days'));
            $to   = $_GET['to']   ?? date('Y-m-d');
            $stmt = $db->prepare("SELECT t.completed_at AS 'Когда отмечено', u.name AS 'Кто дал',
                       a.name AS 'Животное', r.name AS 'Маршрут', a.room AS 'Комната',
                       p.medication_name AS 'Препарат', p.dosage AS 'Доза',
                       p.administration_route AS 'Путь введения', p.`group` AS 'Группа',
                       t.date AS 'Дата задачи', t.time_of_day AS 'Слот'
                FROM tasks t JOIN procedures p ON t.procedure_id=p.id JOIN animals a ON t.animal_id=a.id
                LEFT JOIN routes r ON a.route_id=r.id LEFT JOIN users u ON t.completed_by=u.id
                WHERE t.is_completed=1 AND t.date BETWEEN ? AND ?
                ORDER BY t.completed_at DESC");
            $stmt->execute([$from, $to]);
            $rows = $stmt->fetchAll();
            $name = 'istoriya_vydachi_' . $from . '_' . $to;
            break;

        case 'vaccinations':
            $from = $_GET['from'] ?? date('Y-m-01');
            $to   = $_GET['to']   ?? date('Y-m-d');
            $stmt = $db->prepare("SELECT v.done_date AS 'Дата', a.name AS 'Животное', a.species AS 'Вид',
                       r.name AS 'Маршрут', v.vaccine_name AS 'Вакцина', v.doses AS 'Доз',
                       COALESCE(t.name,'') AS 'Тип', v.next_date AS 'Следующая',
                       CASE WHEN t.is_primary=1 THEN 'первичная' WHEN t.is_primary=0 THEN 'повторная' ELSE '' END AS 'Первичная/повторная',
                       u.name AS 'Внёс', v.note AS 'Примечание'
                FROM vaccinations v JOIN animals a ON v.animal_id=a.id
                LEFT JOIN routes r ON a.route_id=r.id
                LEFT JOIN vaccination_types t ON v.type_id=t.id
                LEFT JOIN users u ON v.created_by=u.id
                WHERE v.done_date BETWEEN ? AND ? ORDER BY v.done_date DESC");
            $stmt->execute([$from, $to]);
            $rows = $stmt->fetchAll();
            $name = 'vakcinacii_' . $from . '_' . $to;
            break;

        case 'staff':
            $date = $_GET['date'] ?? date('Y-m-d');
            $stmt = $db->prepare("SELECT u.name AS 'Сотрудник', r.name AS 'Маршрут',
                       COUNT(*) AS 'Выполнено', MIN(t.completed_at) AS 'Начал', MAX(t.completed_at) AS 'Последняя отметка'
                FROM tasks t JOIN users u ON t.completed_by=u.id JOIN animals a ON t.animal_id=a.id
                LEFT JOIN routes r ON a.route_id=r.id
                WHERE t.date=? AND t.is_completed=1
                GROUP BY u.id, u.name, r.id, r.name ORDER BY u.name, COUNT(*) DESC");
            $stmt->execute([$date]);
            $rows = $stmt->fetchAll();
            $name = 'sotrudniki_' . $date;
            break;

        default:
            err('Неизвестный тип выгрузки: ' . $type, 400);
    }

    if (ob_get_level()) ob_end_clean();
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $name . '.csv"');

    $out = fopen('php://output', 'w');
    // BOM — без него Excel открывает кириллицу в CSV кракозябрами.
    fwrite($out, "\xEF\xBB\xBF");
    if ($rows) {
        fputcsv($out, array_keys($rows[0]), ';');
        foreach ($rows as $r) fputcsv($out, array_values($r), ';');
    } else {
        fwrite($out, "Нет данных\n");
    }
    fclose($out);
    exit;
}

// ── VERIFY TOKEN ──────────────────────────────────────────────
function verifyHandler(): void {
    // Здесь была своя проверка токена — только старого образца,
    // sha256(id + соль). Токены такого вида перестали приниматься 28.07
    // (LEGACY_TOKEN_UNTIL), а вход с тех пор выдаёт токены нового образца,
    // привязанные к личному секрету. Из-за этого autoLogin получал 401,
    // стирал сохранённый токен — и человек вводил пароль при каждом запуске.
    // Проверку ведём той же функцией, что и все остальные запросы.
    $u = currentUser();
    if (!$u) err('Invalid token', 401);
    ok(['user' => $u]);
}
// ── DEBUG (remove after testing) ──────────────────────────────
function debugHandler(): void {
    // Smoke-тест деплоя: подтверждает, что PHP исполняется и база отвечает.
    // Наружу отдаёт только факт работоспособности. Счётчики таблиц и версия
    // PHP убраны: эндпоинт публичный, и постороннему эти данные видеть незачем.
    try {
        db()->query('SELECT 1')->fetchColumn();
    } catch (Throwable $e) {
        err('db unavailable', 503);
    }
    ok(['status' => 'ok']);
}

// AUTH DEBUG удалён: эндпоинт раскрывал логины, роли, email, превью
// хешей паролей и подтверждал хеш реального пароля из регламента деплоя.
