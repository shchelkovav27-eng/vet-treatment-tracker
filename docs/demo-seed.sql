-- Демонстрационные данные: вымышленные сотрудники и животные.
-- Пароль у всех демо-учёток: demo-pass-2026 (только для локального запуска).

INSERT INTO routes (id, name, description) VALUES
  ('r-quarantine', 'Карантин', 'Новые поступления'),
  ('r-cats',       'Кошачий блок', 'Основное содержание кошек'),
  ('r-dogs',       'Собачий блок', 'Вольеры');

INSERT INTO users (id, name, email, username, role, password_hash, is_active) VALUES
  ('u-admin',  'Техадмин Демо',      'admin@example.com',    'admin',    'techAdmin',    '$2y$12$M9lPguXZM.qKj1k8lK0vZenriJ0VkREFwltPkuNfKMdVMFCSU.Ok2', 1),
  ('u-doctor', 'Петрова Анна',       'doctor@example.com',   'petrova',  'doctor',       '$2y$12$M9lPguXZM.qKj1k8lK0vZenriJ0VkREFwltPkuNfKMdVMFCSU.Ok2', 1),
  ('u-shelter','Сидоров Олег',       'shelter@example.com',  'sidorov',  'shelterAdmin', '$2y$12$M9lPguXZM.qKj1k8lK0vZenriJ0VkREFwltPkuNfKMdVMFCSU.Ok2', 1),
  ('u-exec',   'Волонтёр Иванова',   'volunteer@example.com','ivanova',  'executor',     '$2y$12$M9lPguXZM.qKj1k8lK0vZenriJ0VkREFwltPkuNfKMdVMFCSU.Ok2', 1);

INSERT INTO animals (id, name, species, gender, status, route_id, room, cage_number, is_active, created_at) VALUES
  ('a-1', 'Барсик', 'cat', 'male',   'stable',   'r-quarantine', 'Кабинет 1', '3', 1, NOW()),
  ('a-2', 'Мурка',  'cat', 'female', 'stable',   'r-cats',       'Комната 2', '7', 1, NOW()),
  ('a-3', 'Шарик',  'dog', 'male',   'critical', 'r-dogs',       'Вольер 4',  '',  1, NOW());

-- Курсы: задачи на ближайшие дни создаст api.php (r=maintenance или при открытии приложения).
INSERT INTO procedures (id, animal_id, medication_name, dosage, `group`, administration_route,
                        doctor_name, period_type, start_date, course_end_date, time_slots, created_at) VALUES
  ('p-1', 'a-1', 'Антибиотик (демо)', '0,5 мл', 'Лечение', 'п/к', 'Петрова Анна', 'daily',
   CURDATE(), DATE_ADD(CURDATE(), INTERVAL 7 DAY), '["slot_09_10","slot_19_20"]', NOW()),
  ('p-2', 'a-3', 'Капли глазные (демо)', '1 капля', 'Лечение', 'местно', 'Петрова Анна', 'everyNDays',
   CURDATE(), NULL, '["slot_10_11"]', NOW());
UPDATE procedures SET every_n_days = 2 WHERE id = 'p-2';
