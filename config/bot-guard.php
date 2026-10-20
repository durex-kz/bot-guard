<?php

return [

	/*
	| Выключатель фильтра: false — middleware пропускает все запросы
	*/
	'enabled' => env('BOT_GUARD_ENABLED', true),

	/*
	| Таблица и модель справочника заблокированных IP
	*/
	'table' => 'banned_ips',

	'model' => \DurexKz\BotGuard\Models\BannedIp::class,

	/*
	| Модель пользователя для связи creator. null — auth.providers.users.model
	*/
	'user_model' => null,

	/*
	| Gate, который пускает к справочнику. Определяется в приложении:
	| Gate::define('security-admin', fn (User $user) => $user->isGlobalAdmin());
	*/
	'admin_gate' => 'security-admin',

	'policy' => \DurexKz\BotGuard\Policies\BannedIpPolicy::class,

	/*
	| Автоблокировка: после probes_to_ban запросов сканера из одной подсети за probes_window_minutes
	| минут IP заносится в справочник на auto_ban_hours часов, а с ним блокируется его подсеть.
	| Порог больше одного — чтобы одна случайная ссылка пользователя за общим IP (офис, мобильный
	| оператор) не закрывала сайт всей подсети
	*/
	'probes_to_ban' => 3,

	'probes_window_minutes' => 10,

	'auto_ban_hours' => 24,

	/*
	| Размер блокируемой подсети: сканеры перебирают адреса соседних хостов одного хостинга.
	| Для IPv6 /64 — это сеть одного клиента; /24 в IPv6 закрыл бы целого провайдера
	*/
	'ipv4_prefix' => 24,

	'ipv6_prefix' => 64,

	/*
	| Адреса, которые фильтр не трогает совсем (шаблоны Request::is): проверка работоспособности —
	| балансировщик может обращаться по IP, а это правило сканеров
	*/
	'except' => ['up'],

	/*
	| Адреса, где существующие маршруты правилами сканеров не проверяются: внешние интеграции могут
	| ходить скриптовыми клиентами (python-requests и т. п.). Несуществующие адреса (чужие API,
	| которые перебирают сканеры) проверяются как обычно. Блокировка подсети действует и здесь
	*/
	'trust_existing_routes' => ['api/*'],

	/*
	| Дополнительные правила распознавания (фрагменты регулярных выражений, без ограничителей).
	| Встроенные правила — в \DurexKz\BotGuard\ScannerDetector
	*/
	'rules' => [
		// путь запроса: '/(old-admin|backup)(/|$)'
		'paths' => [],
		// адрес вместе с query (дважды декодированный): '[?&]debug_token='
		'uris' => [],
		// User-Agent: 'badbot|evilcrawler'
		'user_agents' => [],
		// классы, реализующие \DurexKz\BotGuard\Contracts\ScannerRule
		'custom' => [],
	],

	/*
	| Методы, которыми пользуется сайт; остальные (PROPFIND, TRACE, CONNECT…) — признак сканера
	*/
	'allowed_methods' => ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

	/*
	| Писать запросы сканеров в журнал ошибок (если установлен durex-kz/error-monitor)
	*/
	'log_to_error_monitor' => true,

	/*
	| Ответ сканеру и заблокированной подсети: 404, а не 403 — не сообщаем, что его распознали.
	| Без шаблона ошибки и сессии: ответ должен быть дешёвым
	*/
	'response' => [
		'status' => 404,
		'body' => 'Not Found',
	],

	'cache_key' => 'banned-ips',

	'run_migrations' => true,

];
