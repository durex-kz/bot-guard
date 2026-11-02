# durex-kz/bot-guard

Фильтр сканеров уязвимостей для Laravel 12/13. Стоит в глобальном стеке middleware, до сессии и маршрутизации, поэтому отказ сканеру почти ничего не стоит.

- **Распознаёт** перебор `.env`, `.git`, `phpinfo`, бэкапов и `wp-login`, служебные адреса чужих фреймворков, VPN и панелей, обход каталогов, SQL-инъекции, XSS, Log4Shell, нагрузки RCE в теле запроса к несуществующим адресам (React Server Components / Next.js), известные сканеры по User-Agent, запросы по IP вместо домена и необычные HTTP-методы.
- **Отвечает 404**, а не 403, чтобы сканер не понял, что его распознали. Запрос пишется в журнал ошибок с пометкой `is_scanner`, если установлен [`durex-kz/error-monitor`](https://github.com/durex-kz/error-monitor).
- **Автоблокировка.** После 3 запросов сканера из одной подсети за 10 минут IP попадает в справочник на 24 часа вместе со всей подсетью (`/24`, для IPv6 `/64`). Запросы из заблокированной подсети отклоняются по кэшу, без обращения к базе.
- **Повторные атаки.** Если подсеть снова атакует в течение суток после окончания блокировки (с того же или другого IP), следующая автоблокировка в 2 раза длиннее: 24 часа → 2 дня → 4 дня → 8 дней…, но не больше 10 лет. Вернулась позже — счёт начинается заново.
- **Белый список.** Подсеть из белого списка фильтр не трогает до указанного срока (1, 7, 30 дней или навсегда). Запись создаётся из заблокированного IP (действие в панели или `bot-guard:allow`): блокировка завершается, а в записи остаются ссылка на неё и её снимок — видно, откуда взялось разрешение.
- **Не блокирует** частные и локальные адреса, проверку `/up`, существующие маршруты `api/*` (интеграции, которые ходят через `python-requests`) и поисковых роботов.

Справочник и виджет для панели находятся в [`durex-kz/filament-security`](https://github.com/durex-kz/filament-security).

## Установка

```bash
composer require durex-kz/bot-guard
php artisan migrate
```

`bootstrap/app.php`. Middleware ставится после TrustProxies, потому что ему нужен настоящий IP клиента.
Доверять стоит только своим прокси, не `'*'`: если nginx передаёт запрос в PHP напрямую, с `'*'` любой посетитель
подставляет себе IP заголовком `X-Forwarded-For: 127.0.0.1` — частные адреса не блокируются, и сканер проходит
мимо блокировок и ограничений попыток по IP:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->trustProxies(at: ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']);
    $middleware->append(\DurexKz\BotGuard\Http\Middleware\BlockScanners::class);
})
```

Доступ к справочнику в панели даёт тот же gate `security-admin`, что и в error-monitor.

## Настройка

```bash
php artisan vendor:publish --tag=bot-guard-config
```

| Ключ | По умолчанию | Назначение |
|---|---|---|
| `probes_to_ban` / `probes_window_minutes` | `3` / `10` | порог автоблокировки |
| `auto_ban_hours` | `24` | срок автоблокировки |
| `auto_ban_multiplier` | `2` | во сколько раз длиннее каждая повторная автоблокировка подсети (`1` — без роста) |
| `auto_ban_repeat_window_hours` | `24` | повтором считается атака не позже стольких часов после окончания блокировки (`null` — в любое время) |
| `auto_ban_max_hours` | `87600` | наибольший срок автоблокировки (10 лет) |
| `not_found_burst` / `not_found_burst_seconds` | `5` / `10` | перебор адресов: столько разных 404 с одного IP за столько секунд — сканер (`0` — выключено) |
| `not_found_burst_except_user_agents` | поисковые роботы | User-Agent, которые правило перебора не трогает |
| `ipv4_prefix` / `ipv6_prefix` | `24` / `64` | размер блокируемой подсети |
| `except` | `['up']` | адреса, которые фильтр не трогает |
| `trust_existing_routes` | `['api/*']` | существующие маршруты без проверки правил |
| `rules.paths` / `rules.uris` / `rules.user_agents` | `[]` | свои правила (фрагменты регулярных выражений) |
| `rules.custom` | `[]` | классы `DurexKz\BotGuard\Contracts\ScannerRule` |
| `enabled` | `true` | выключатель (`BOT_GUARD_ENABLED=false`) |

```php
'rules' => [
    'paths' => ['/old-admin(/|$)'],
    'user_agents' => ['badbot'],
],
```

## Команды

```bash
php artisan bot-guard:ban 203.0.113.5 --hours=48 --reason="Перебор паролей"
php artisan bot-guard:unban 203.0.113.77   # снимает блокировку всей подсети и сбрасывает счёт её повторов
php artisan bot-guard:allow 203.0.113.77 --days=7 --reason="Офис за общим IP"   # белый список; без --days — навсегда
php artisan bot-guard:allow-country RU --days=30 --reason="Партнёры"   # белый список стран; без кода — показать список
```

## Страна и город

При блокировке страна и город IP определяются по локальной базе [MaxMind GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
и сохраняются в записи (`country_code`, `country`, `city`): в сеть ничего не уходит, поиск — доли миллисекунды,
страница справочника просто читает готовые поля. Нет базы — блокировка работает как обычно, поля пустые.

1. Бесплатная учётная запись на maxmind.com → GeoLite2 → «Manage License Keys» → новый ключ. В `.env`:

   ```dotenv
   MAXMIND_ACCOUNT_ID=123456
   MAXMIND_LICENSE_KEY=xxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_mmk
   ```

2. Скачать базу (~60 МБ в `storage/app/geoip/GeoLite2-City.mmdb`) — команда сразу заполнит место у уже заблокированных IP:

   ```bash
   php artisan bot-guard:geoip-update
   ```

3. Обновлять раз в неделю (`routes/console.php`):

   ```php
   Schedule::command('bot-guard:geoip-update')->weekly();
   ```

`php artisan bot-guard:geoip-fill --all` — определить место заново у всех записей. Настройки — `geoip` в конфиге
(путь к базе `BOT_GUARD_GEOIP_DATABASE`, язык названий `locales`, по умолчанию русский, иначе английский).

## Белый список стран

Пока в справочнике `allowed_countries` есть действующие записи, сайт отвечает только посетителям из этих стран,
остальным — `403` с текстом «обращения из вашей страны (…) к этому сайту не разрешены» (`countries.response`).
Страна IP — по той же базе GeoLite2 (раздел выше).

- **Страна размещения сайта разрешена всегда.** Её код — `BOT_GUARD_HOME_COUNTRY`, по умолчанию страна часового
  пояса приложения (`APP_TIMEZONE=Asia/Almaty` → `KZ`). Если действующей записи о ней нет (не было, удалили,
  истёк срок), она добавляется автоматически на 10 лет (`countries.home_years`).
- **Порядок проверок:** белый список IP → белый список стран → блокировки подсетей → правила сканеров.
  Белый список IP главнее: разрешённая подсеть проходит из любой страны (внешние сервисы, сотрудники в командировке).
- **Не ограничиваются:** частные адреса, IP, которых нет в базе, сайт без базы GeoLite2, адреса из `except`.
- Выключить — `BOT_GUARD_COUNTRIES=false`.

Поисковые роботы (Googlebot, Bingbot) ходят в основном из США: если страны США нет в списке, сайт пропадёт из их выдачи.

## Переход с кода в проекте (QazPress, «Апельсин»)

Таблица `banned_ips` и миграция `2026_10_20_120000_create_banned_ips_table` остаются прежними, данные сохраняются.

1. `composer require durex-kz/bot-guard`
2. Удалить `app/Http/Middleware/BlockScanners.php`, `app/Models/BannedIp.php`, `app/Policies/BannedIpPolicy.php` и миграцию `2026_10_20_120000_create_banned_ips_table.php`.
3. В `bootstrap/app.php` заменить `\App\Http\Middleware\BlockScanners::class` на `\DurexKz\BotGuard\Http\Middleware\BlockScanners::class`.
4. Заменить `ErrorLog::isScannerProbe(...)` на `app(\DurexKz\BotGuard\ScannerDetector::class)->isProbe(...)`.

Правила обоих проектов объединены. В «Апельсин» добавились правила QazPress (робот спам-ссылок `seo-health-probe` и `?_dispatch_probe=`) и пропуск существующих маршрутов `api/*`. В QazPress добавились `?rest_route=` и запрет блокировать частные адреса из «Апельсина».

## Тесты

```bash
composer test
```

## Лицензия

MIT
