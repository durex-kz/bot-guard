# durex-kz/bot-guard

Фильтр сканеров уязвимостей для Laravel 12/13. Стоит в глобальном стеке middleware, до сессии и маршрутизации, поэтому отказ сканеру почти ничего не стоит.

- **Распознаёт** перебор `.env`, `.git`, `phpinfo`, бэкапов и `wp-login`, служебные адреса чужих фреймворков, VPN и панелей, обход каталогов, SQL-инъекции, XSS, Log4Shell, известные сканеры по User-Agent, запросы по IP вместо домена и необычные HTTP-методы.
- **Отвечает 404**, а не 403, чтобы сканер не понял, что его распознали. Запрос пишется в журнал ошибок с пометкой `is_scanner`, если установлен [`durex-kz/error-monitor`](https://github.com/durex-kz/error-monitor).
- **Автоблокировка.** После 3 запросов сканера из одной подсети за 10 минут IP попадает в справочник на 24 часа вместе со всей подсетью (`/24`, для IPv6 `/64`). Запросы из заблокированной подсети отклоняются по кэшу, без обращения к базе.
- **Повторные атаки.** Если подсеть атакует снова после истечения блокировки (с того же или другого IP), срок каждой следующей автоблокировки в 2 раза длиннее: 24 часа → 2 дня → 4 дня → 8 дней…, но не больше 10 лет.
- **Не блокирует** частные и локальные адреса, проверку `/up`, существующие маршруты `api/*` (интеграции, которые ходят через `python-requests`) и поисковых роботов.

Справочник и виджет для панели находятся в [`durex-kz/filament-security`](https://github.com/durex-kz/filament-security).

## Установка

```bash
composer require durex-kz/bot-guard
php artisan migrate
```

`bootstrap/app.php`. Middleware ставится после TrustProxies, потому что ему нужен настоящий IP клиента:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->trustProxies(at: '*');
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
```

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
