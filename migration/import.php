<?php
// Импорт расхождения Firebase → MySQL: данные, записанные в старую систему
// уже после основной миграции (период между переездом и отключением Firebase).
//   php import.php           — холостой прогон, ничего не пишет
//   php import.php --apply   — запись; данные идут одной транзакцией
declare(strict_types=1);
mb_internal_encoding('UTF-8');

$APPLY = in_array('--apply', $argv, true);
$cfg = require __DIR__ . '/../apps/treatment-tracker/config.php';
$db = new PDO(
    "mysql:host={$cfg['db_host']};dbname={$cfg['db_name']};charset=utf8mb4",
    $cfg['db_user'], $cfg['db_pass'],
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
);

// Один сотрудник оказался заведён дважды: до миграции в Firebase и заново в
// новой системе. Сливаем в mysql-аккаунт, firebase-идентификатор не создаём.
// Идентификаторы ниже — заглушки; в реальном прогоне подставляются свои.
const FB_DUP_USER = '00000000-0000-4000-8000-000000000001';
const MY_DUP_USER = '00000000-0000-4000-8000-000000000002';
$uid = fn(?string $u) => $u === FB_DUP_USER ? MY_DUP_USER : $u;

$P = json_decode(file_get_contents(__DIR__ . '/payload.json'), true, 512, JSON_THROW_ON_ERROR);
$A = json_decode(file_get_contents(__DIR__ . '/audit_payload.json'), true, 512, JSON_THROW_ON_ERROR);

function dt(?string $v): ?string { if (!$v) return null; $t = strtotime($v); return $t ? date('Y-m-d H:i:s', $t) : null; }
function dd(?string $v): ?string { if (!$v) return null; $t = strtotime($v); return $t ? date('Y-m-d', $t) : null; }
function js($v): ?string { return ($v === null || $v === []) ? null : json_encode($v, JSON_UNESCAPED_UNICODE); }

// ── Колонка под детализацию журнала ──────────────────────────────
// «Было/стало» и метаданные из Firebase хранить негде: в audit_logs таких
// колонок нет. Добавляем одну nullable-колонку — auditHandler и logAudit
// перечисляют поля поимённо, поэтому для API изменение невидимо.
$hasDetails = (bool)$db->query("SHOW COLUMNS FROM audit_logs LIKE 'details'")->fetch();
if (!$hasDetails) {
    echo $APPLY ? ">>> добавляю колонку audit_logs.details\n" : ">>> потребуется колонка audit_logs.details (будет добавлена)\n";
    // DDL в MySQL неявно фиксирует транзакцию — поэтому строго ДО её начала.
    if ($APPLY) $db->exec("ALTER TABLE audit_logs ADD COLUMN details TEXT NULL");
}

// ── Проверка целостности до любой записи ─────────────────────────
$have = fn(string $t) => array_flip($db->query("SELECT id FROM `$t`")->fetchAll(PDO::FETCH_COLUMN));
$animals = $have('animals'); $procs = $have('procedures'); $users = $have('users');
foreach ($P['animals'] as $a) $animals[$a['id']] = true;
foreach ($P['procedures'] as $p) $procs[$p['id']] = true;
$newUser = null;
foreach ($P['users'] as $u) if ($u['id'] !== FB_DUP_USER) { $users[$u['id']] = true; $newUser = $u; }

$bad = [];
foreach ($P['procedures'] as $p) if (!isset($animals[$p['animalId'] ?? ''])) $bad[] = "процедура {$p['id']}: нет животного";
foreach ($P['tasks'] as $t) {
    if (!isset($animals[$t['animalId'] ?? ''])) $bad[] = "задача {$t['id']}: нет животного";
    if (!isset($procs[$t['procedureId'] ?? ''])) $bad[] = "задача {$t['id']}: нет процедуры";
    $cb = $uid($t['completedBy'] ?? null);
    if ($cb && !isset($users[$cb])) $bad[] = "задача {$t['id']}: нет исполнителя $cb";
}
foreach ($A as $r) { $u = $r['user_id']; if ($u && !isset($users[$u])) $bad[] = "журнал {$r['id']}: нет автора $u"; }

echo "=== ПРОВЕРКА ЦЕЛОСТНОСТИ ===\n";
if ($bad) {
    echo "битых ссылок: ", count($bad), "\n";
    foreach (array_slice($bad, 0, 10) as $x) echo "  ! $x\n";
    if ($APPLY) { echo "\nОТКАЗ: запись отменена\n"; exit(1); }
} else echo "битых ссылок нет\n";
echo "\n", $APPLY ? ">>> РЕЖИМ ЗАПИСИ\n\n" : ">>> ХОЛОСТОЙ ПРОГОН, база не изменяется\n\n";

// ── Раскладка задач: часть слотов уже создана системой ───────────
// uniq_task = (procedure_id, animal_id, date, time_of_day). Новая система
// нагенерировала эти слоты пустыми, поэтому выполнение проставляем в них,
// а вставляем только те задачи, слотов для которых нет.
$slot = [];
foreach ($db->query("SELECT id, procedure_id, animal_id, date, time_of_day FROM tasks") as $r)
    $slot["{$r['procedure_id']}|{$r['animal_id']}|{$r['date']}|{$r['time_of_day']}"] = $r['id'];

$toUpdate = $toInsert = [];
foreach ($P['tasks'] as $t) {
    $k = "{$t['procedureId']}|{$t['animalId']}|" . dd($t['date']) . "|{$t['timeOfDay']}";
    if (isset($slot[$k])) $toUpdate[] = [$slot[$k], $t]; else $toInsert[] = $t;
}

$n = [];
if ($APPLY) $db->beginTransaction();

$ins = function (string $sql, array $rows, callable $map) use ($db, $APPLY) {
    $st = $db->prepare($sql);
    foreach ($rows as $r) if ($APPLY) $st->execute($map($r));
    return count($rows);
};

$n['животные'] = $ins(
  "INSERT INTO animals (id,name,species,gender,status,route_id,room,cage_number,notes,allergies,blood_type,hiv_status,leukemia_status,photo_url,is_active,created_at)
   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", $P['animals'],
  fn($a) => [$a['id'],$a['name'],$a['species'],$a['gender'],$a['status'],$a['routeId'],$a['room'],$a['cageNumber'],
             $a['notes'],$a['allergies'],$a['bloodType'],$a['hivStatus'],$a['leukemiaStatus'],$a['photoUrl'],
             $a['isActive']?1:0, dt($a['createdAt'])]);

$n['процедуры'] = $ins(
  "INSERT INTO procedures (id,animal_id,medication_name,dosage,`group`,administration_route,doctor_name,frequency,period_type,duration_days,start_date,course_end_date,course_end_type,total_repetitions,every_n_days,yearly_date,notes,time_slots,week_days,month_days,cycle_config,created_at)
   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", $P['procedures'],
  fn($p) => [$p['id'],$p['animalId'],$p['medicationName'],$p['dosage'],$p['group'],$p['administrationRoute'],
             $p['doctorName'],$p['frequency'],$p['periodType'],$p['durationDays'],dd($p['startDate']),
             dd($p['courseEndDate']),$p['courseEndType'],$p['totalRepetitions'],$p['everyNDays'],$p['yearlyDate'],
             $p['notes'],js($p['timeSlots']),js($p['weekDays']),js($p['monthDays']),js($p['cycleConfig']),
             dd($p['startDate']) ? dd($p['startDate']) . ' 00:00:00' : null]);

// Действительно новый сотрудник. Логин по фамилии, как у всех (makeUsername).
// Пароль переносится хешем: verifyPassword() умеет старый SHA-256.
$n['сотрудники'] = $newUser ? $ins(
  "INSERT INTO users (id,name,email,username,role,password_hash,is_active,is_first_login,created_at)
   VALUES (?,?,?,?,?,?,1,?,?)", [$newUser],
  fn($u) => [$u['id'],$u['name'],$u['email'],'newemployee',$u['role'],$u['passwordHash'],
             $u['isFirstLogin']?1:0, date('Y-m-d H:i:s')]) : 0;

// Слитому сотруднику по решению команды назначается роль врача.
if ($APPLY) $db->prepare("UPDATE users SET role='doctor' WHERE id=?")->execute([MY_DUP_USER]);
$n['роль слитого сотрудника → doctor'] = 1;

$n['задачи: отмечено выполненными'] = (function () use ($db, $APPLY, $toUpdate, $uid) {
    $st = $db->prepare("UPDATE tasks SET is_completed=1, completed_by=?, completed_at=?, notes=COALESCE(?, notes) WHERE id=?");
    foreach ($toUpdate as [$id, $t]) if ($APPLY) $st->execute([$uid($t['completedBy']), dt($t['completedAt']), $t['notes'], $id]);
    return count($toUpdate);
})();

$n['задачи: добавлено'] = $ins(
  "INSERT INTO tasks (id,animal_id,procedure_id,date,time_of_day,is_completed,completed_by,completed_at,notes,created_at)
   VALUES (?,?,?,?,?,1,?,?,?,?)", $toInsert,
  fn($t) => [$t['id'],$t['animalId'],$t['procedureId'],dd($t['date']),$t['timeOfDay'],
             $uid($t['completedBy']),dt($t['completedAt']),$t['notes'],dd($t['date']) . ' 00:00:00']);

$n['журнал аудита'] = $ins(
  "INSERT INTO audit_logs (id,action_type,description,target_id,target_name,target_type,user_id,user_name,timestamp,details)
   VALUES (?,?,?,?,?,?,?,?,?,?)", $A,
  fn($r) => [$r['id'],$r['action_type'],$r['description'],$r['target_id'],$r['target_name'],$r['target_type'],
             $r['user_id'],$r['user_name'],dt($r['timestamp']),$r['details']]);

if ($APPLY) { $db->commit(); echo ">>> ТРАНЗАКЦИЯ ЗАФИКСИРОВАНА\n\n"; }

echo "=== ИТОГ ===\n";
foreach ($n as $k => $v) printf("  %-32s %6d %s\n", $k, $v, $APPLY ? '✓' : '(к записи)');
