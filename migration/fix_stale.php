<?php
// Догоняем статусы задач, которые уехали в MySQL при миграции невыполненными,
// а галочку получили в Firebase уже после миграции. Ключ — не id, а
// бизнес-связка (процедура, животное, дата, слот).
declare(strict_types=1);
$APPLY = in_array('--apply', $argv, true);
$cfg = require __DIR__ . '/../apps/treatment-tracker/config.php';
$db = new PDO("mysql:host={$cfg['db_host']};dbname={$cfg['db_name']};charset=utf8mb4",
    $cfg['db_user'], $cfg['db_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$rows = json_decode(file_get_contents(__DIR__ . '/stale_tasks.json'), true, 512, JSON_THROW_ON_ERROR);

$users = array_flip($db->query("SELECT id FROM users")->fetchAll(PDO::FETCH_COLUMN));
$bad = 0;
foreach ($rows as $r) if ($r['completed_by'] && !isset($users[$r['completed_by']])) $bad++;
echo "записей: ", count($rows), ", с неизвестным исполнителем: $bad\n";
if ($bad) { echo "ОТКАЗ\n"; exit(1); }

if (!$APPLY) { echo ">>> холостой прогон, база не изменяется\n"; exit(0); }
$db->beginTransaction();
$st = $db->prepare("UPDATE tasks SET is_completed=1, completed_by=?, completed_at=?, notes=COALESCE(?, notes)
                    WHERE procedure_id=? AND animal_id=? AND date=? AND time_of_day=? AND is_completed=0");
$n = 0;
foreach ($rows as $r) {
    $st->execute([$r['completed_by'], $r['completed_at'] ? date('Y-m-d H:i:s', strtotime($r['completed_at'])) : null,
                  $r['notes'], $r['procedure_id'], $r['animal_id'], $r['date'], $r['time_of_day']]);
    $n += $st->rowCount();
}
$db->commit();
echo "обновлено строк: $n\n";
