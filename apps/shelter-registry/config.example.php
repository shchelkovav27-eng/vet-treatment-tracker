<?php
// Скопируйте в config.php (он в .gitignore) и заполните своими значениями.
// Лучше положить config.php на уровень ВЫШЕ веб-корня: api.php ищет его
// сначала в ../config.php, затем рядом с собой.
return [
    'db_host'    => 'localhost',
    'db_name'    => 'shelter',
    'db_user'    => 'shelter_app',
    'db_pass'    => 'CHANGE_ME',

    // Соль для токенов старого образца (только для обратной совместимости).
    'token_salt' => 'CHANGE_ME_random_string',

    // Ключ для планировщика (cron): GET api.php?r=maintenance&key=...
    // Пустая строка — вход по ключу выключен.
    'maint_key'  => '',
];
