# Changelog

## v0.1.2 — 2026-10-21

- Правила сканеров: SQL-инъекции по синтаксическим признакам — подбор числа столбцов (`ORDER BY 1-- -`),
  ошибки приведения типов SQL Server (`CONVERT(INT,…)`, `CAST(… AS INT)`), тавтология после кавычки или скобки
  (`' AND 1=1`, `) AND (123=123'`), комментарий сразу после кавычки (`'-- -`), служебные объекты СУБД
  (`information_schema`, `@@version`, `xp_cmdshell`, `pg_sleep`, `extractvalue(`, `updatexml(`).
  Обычный поиск со словами «order by», «select», «and» под правила не попадает.

## v0.1.1 — 2026-10-21

- Правило сканеров: файлы зависимостей с версиями пакетов — `composer.json`, `composer.lock`,
  `vendor/composer/installed.json`, `package.json`, `package-lock.json`, `yarn.lock`.

## v0.1.0 — 2026-10-20

- Первая версия: код вынесен из проектов QazPress и «Апельсин» и объединён.
