-- Базовая схема MySQL 8 (utf8mb4).
-- Остальные таблицы (места, справочник препаратов, пристройство, вакцинации,
-- медицина) и недостающие колонки api.php создаёт сам при первом обращении
-- (функции ensure*), поэтому здесь только ядро.

CREATE TABLE routes (
  id VARCHAR(36) PRIMARY KEY, name VARCHAR(100), description TEXT,
  created_at DATETIME DEFAULT NOW()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE animals (
  id VARCHAR(36) PRIMARY KEY, name VARCHAR(255), species VARCHAR(20) DEFAULT 'cat',
  gender VARCHAR(20) DEFAULT 'unknown', status VARCHAR(50) DEFAULT 'stable',
  route_id VARCHAR(36), room VARCHAR(100), cage_number VARCHAR(50),
  notes TEXT, allergies TEXT, blood_type VARCHAR(20), hiv_status VARCHAR(50),
  leukemia_status VARCHAR(50), photo_url TEXT, is_active TINYINT(1) DEFAULT 1,
  created_at DATETIME, updated_at DATETIME DEFAULT NOW(),
  KEY idx_route (route_id), KEY idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE users (
  id VARCHAR(36) PRIMARY KEY, name VARCHAR(255), email VARCHAR(255),
  username VARCHAR(50) UNIQUE,
  role VARCHAR(50) DEFAULT 'executor',          -- techAdmin | doctor | shelterAdmin | executor
  password_hash VARCHAR(255),                   -- bcrypt; legacy SHA-256 принимается и перехешируется
  is_active TINYINT(1) DEFAULT 1, is_first_login TINYINT(1) DEFAULT 0,
  created_at DATETIME DEFAULT NOW()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Назначение (курс лечения). Периодичность: daily | everyNDays | weekly | monthly | yearly | cycle
CREATE TABLE procedures (
  id VARCHAR(36) PRIMARY KEY, animal_id VARCHAR(36), medication_name VARCHAR(255),
  dosage VARCHAR(255), `group` VARCHAR(100), administration_route VARCHAR(100),
  doctor_name VARCHAR(255), frequency INT DEFAULT 1, period_type VARCHAR(50) DEFAULT 'daily',
  duration_days INT, start_date DATE, course_end_date DATE, course_end_type VARCHAR(50),
  total_repetitions INT, every_n_days INT, yearly_date VARCHAR(20), notes TEXT,
  time_slots TEXT, week_days TEXT, month_days TEXT, cycle_config TEXT,
  created_at DATETIME DEFAULT NOW(), updated_at DATETIME DEFAULT NOW(),
  KEY idx_animal (animal_id), KEY idx_end (course_end_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Ежедневная задача исполнителю. UNIQUE делает генерацию идемпотентной.
CREATE TABLE tasks (
  id VARCHAR(36) PRIMARY KEY, animal_id VARCHAR(36), procedure_id VARCHAR(36),
  date DATE, time_of_day VARCHAR(50), is_completed TINYINT(1) DEFAULT 0,
  completed_by VARCHAR(36), completed_at DATETIME, notes TEXT,
  created_at DATETIME DEFAULT NOW(),
  UNIQUE KEY uniq_task (procedure_id, animal_id, date, time_of_day),
  KEY idx_date (date), KEY idx_animal (animal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE audit_logs (
  id VARCHAR(36) PRIMARY KEY, action_type VARCHAR(100), description TEXT,
  target_id VARCHAR(36), target_name VARCHAR(255), target_type VARCHAR(50),
  user_id VARCHAR(36), user_name VARCHAR(255), timestamp DATETIME DEFAULT NOW(),
  details TEXT NULL,
  KEY idx_ts (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
