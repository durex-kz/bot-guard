<?php

namespace DurexKz\BotGuard;

use DurexKz\BotGuard\Contracts\ScannerRule;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Throwable;

/**
 * Распознавание запросов сканеров уязвимостей: перебор phpinfo, бэкапов, .env/.git, WordPress,
 * VPN/серверных панелей, инъекции в адресе, известные User-Agent сканеров и т. п. У сайта нет
 * таких адресов, поэтому это не битые ссылки, а шум. Дополнительные правила — config bot-guard.rules
 */
class ScannerDetector
{
	/**
	 * Путь: файлы и служебные адреса, которых у сайта нет
	 */
	protected const PATH_RULES = [
		'\.php|/\.(?!well-known/)|/(wp-|wordpress|xmlrpc|cgi-bin|phpmyadmin)',
		'\.(bak|old|orig|save|swp|backup|sql|tar|gz|tgz|zip|rar|7z|ini|log|ya?ml|asp|aspx|jsp|cgi|env|cfg|conf|pem|key)$',
		// служебные адреса других фреймворков и серверов: phpinfo, Symfony profiler, Ignition, Spring actuator…
		'/(phpinfo|info|_profiler|_environment|_ignition|telescope|actuator|server-status|server-info'
		. '|vendor/phpunit|boaform|hnap1|solr|owa|ecp|jenkins|manager/html'
		// VPN и сетевое оборудование (Fortinet, Palo Alto, Pulse, Cisco), Java-серверы, Docker, прочие панели
		. '|remote/login|global-protect|dana-na|\+cscoe\+|sslvpn|vpn|mgmt|gponform|level/15'
		. '|wls-wsat|_async|invoker|jmx-console|web-console|axis2|struts|reportserver|autodiscover'
		. '|druid|nacos|geoserver|api/jsonws|containers/json|v2/_catalog|owncloud|nextcloud'
		. '|administrator|shell|cmd|console|debug/default|(sftp-)?config\.json|enhancecp|etc/passwd'
		// Laravel Debugbar, API чужих сервисов: Metabase (api/session/properties), Airflow (api/v1/dags),
		// Grafana (api/org), OpenAI-совместимые LLM-шлюзы (v1/models)
		. '|_debugbar|api/session/properties|api/v1/dags|api/org|v1/models'
		// файлы зависимостей с версиями пакетов — по ним подбирают известные уязвимости
		. '|composer\.(json|lock)|vendor/composer/installed\.json|package(-lock)?\.json|yarn\.lock'
		// файлы с секретами и ключами доступа: secrets.json, credentials.json, appsettings*.json (.NET),
		// service-account.json (ключ Google Cloud)
		. '|secrets?\.json|credentials?\.json|appsettings(\.[\w-]+)?\.json|service-account\.json'
		// поиск открытых MCP-серверов (Model Context Protocol — подключение ИИ-агентов к инструментам): /mcp, /sse
		. '|mcp|sse'
		// служебные адреса Next.js / React Server Components: на них проверяют React2Shell
		. '|_next|_?_rsc|__nextjs_action|_middleware|rsc/.+\.txt'
		// открытые NoSQL-базы и поисковые движки: CouchDB (_all_dbs, _utils), Elasticsearch (_cluster, _cat, _nodes…)
		. '|_all_dbs|_utils|_cluster|_cat|_nodes|_snapshot|_watcher|_aliases|_mapping)(/|$)',
		// исходники и настройки других платформ (Python, Ruby, Java, .NET, Node.js, Angular, Docker): у PHP-сайта
		// таких файлов нет, по ним ищут ключи и пароли к базам
		'\.(properties|py|rb|enc)$|/dockerfile$|/(web|nuget)(\.[\w-]+)?\.config$|/readme\.md$',
		'/((ts|js)config(\.[\w-]+)?|angular|bundleconfig|launchsettings|hosting|settings|env|meteor\.settings)\.json$',
		// кроме скриптов компонентов Livewire (/livewire-…/js/{component}.js)
		'^(?!/livewire[\w-]*/).*/(ecosystem\.config|(karma|protractor)\.conf|(vue|next|nuxt)\.config|config-overrides|gulpfile|gruntfile'
		. '|setupproxy|setuptests|config|settings|env|constants)\.js$|/environment(\.[\w-]+)?\.ts$',
		// каталоги настроек: /config/aws.json, /src/config/settings.ts, /instance/config.py
		'^/(config|conf|src|instance)/.+\.(js|ts|json|xml)$',
	];

	/**
	 * Адрес и query: обход каталогов, SQL-инъекции, XSS, Log4Shell, PHP/RCE-нагрузки
	 */
	protected const URI_RULES = [
		'\.\./|\.\.\\\\|/etc/passwd|win\.ini|union[\s/*]+(all[\s/*]+)?select|<script|javascript:',
		'\$\{jndi:|\$\{\$\{|allow_url_include|auto_prepend_file|xdebug_session_start|base64_decode\(',
		'\beval\(|sleep\(\d+\)|benchmark\(|waitfor\s+delay|/bin/(ba)?sh|cmd\.exe|\bwget\s|\bcurl\s',
		// SQL-инъекции по синтаксическим признакам (обычный поиск со словами «order by», «select» не задевают):
		// подбор числа столбцов (ORDER BY 1-- -), ошибки приведения типов SQL Server (CONVERT(INT,…), CAST(… AS INT)),
		// тавтология после кавычки или скобки (' AND 1=1, ) AND (123=123'), комментарий сразу после кавычки ('-- -)
		'\border\s+by\s+\d+\s*(--|#|/\*)',
		'\b(convert|cast)\s*\(\s*(int|bigint|varchar|nvarchar|char)\b|\bcast\s*\(.{0,80}\bas\s+(int|bigint|varchar|nvarchar|char)\b',
		// именованная группа: правила склеиваются в одно выражение, номера групп у них общие
		'[\'")]\s*(?:and|or)\s*\(?\s*[\'"]?(?<sqli_n>\d+)[\'"]?\s*=\s*[\'"]?\k<sqli_n>\b',
		'[\'")]\s*(--[\s-]|--$|#|/\*)',
		// служебные объекты СУБД
		'information_schema|@@version|xp_cmdshell|pg_sleep|dbms_pipe|extractvalue\s*\(|updatexml\s*\(',
		// REST API WordPress (/blog/?rest_route=/, /wp/?rest_route=/…): ищут сайт на WordPress под любым каталогом
		'[?&]rest_route=',
		// метка проверочных запросов робота продавца спам-ссылок (?_dispatch_probe=…)
		'[?&]_dispatch_probe=',
	];

	/**
	 * Известные сканеры и сервисы массового сканирования интернета
	 */
	protected const USER_AGENT_RULES = [
		'sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|gobuster|dirbuster|\bdirb\b|ffuf|feroxbuster|wfuzz',
		'acunetix|netsparker|qualys|openvas|nessus|burpsuite|censys|expanse|shodan|l9explore|l9tcpid|leakix',
		'internetmeasurement|modatscanner|bitsightbot|detectify|projectdiscovery|zmeu|morfeus|jorgee',
		'keydrop|alittle client|hello,? ?world|visionheight|\bodin\b|wpbot',
		// робот продавца спам-ссылок, проверяющий свои страницы на чужих сайтах (в том числе с поддельным Googlebot)
		'seo-health-probe',
		// «scanner» — но не приложения-сканеры QR-кодов: по QR открывают документы и отчёты
		'(?<!qr)(?<!qr[- ])scanner',
		// скриптовые HTTP-клиенты: обычные пользователи ими не ходят (существующие API — trust_existing_routes)
		'python-requests|python-urllib|python-httpx|aiohttp|fasthttp',
		// проверки конкретных уязвимостей называют себя по номеру CVE: cve-2026-63030/1.0, metabase-cve-2026-72898-detect
		'\bcve-\d{4}-\d+',
		// сборщики адресов открытых баз данных: nosql-domain-extractor/2.0
		'nosql-',
	];

	/**
	 * Тело запроса: нагрузки удалённого выполнения кода. Проверяется только у запросов без маршрута
	 * (isBodyExploit) — текст собственных форм сайта (статья о Node.js с require('child_process')) не задеваем
	 */
	protected const BODY_RULES = [
		// React Server Components / Next.js («React2Shell»): подмена прототипа в теле Server Action
		// (_formData.get = "$1:constructor:constructor", then = "$1:__proto__:then") и вызов child_process
		'\$\d+:constructor:constructor|:__proto__:then|process\.mainModule|child_process',
		// обфусцированные варианты той же пробы (имена спрятаны в \u005f…, Buffer собирается переворотом строки,
		// нагрузка в base64): признаки, без которых эксплойт не работает, — поля Server Action Next.js
		// ($ACTION_REF_0, $ACTION_0:0, $ACTION_ID_…), ключи протокола RSC (_response, _prefix, resolved_model),
		// подмена прототипа и косвенный eval. Проверяется раскодированное тело (normalizeBody)
		'\$ACTION_(?:REF_\d|ID_|\d+:)|"_response"\s*:|"_prefix"\s*:|resolved_model|__proto__|\(\s*0\s*,\s*eval\s*\)',
		// ботнет Androxgh0st и его клоны: POST / с полем-массивом 0x[]=androxgh0st (0x[]=ridho) — по ответу
		// ищут сайты Laravel с открытым режимом отладки, чтобы забрать .env
		'(?:^|&)0x\[\]=',
		// проверочная проба React2Shell без нагрузки: ссылка RSC на свойство чанка ["$1:aa:aa"] — по ответу
		// сервера видно, обрабатывает ли он Server Actions
		'\[\\\\*"\$\d+:\w+:\w+\\\\*"\]',
	];

	/**
	 * Сколько байт тела проверять: нагрузка эксплойта — в начале, большие загрузки читать целиком незачем
	 */
	protected const BODY_LIMIT = 65536;

	public function isProbe(Request $request, ?int $code = null): bool
	{
		$path = '/' . ltrim(rawurldecode($request->path()), '/');

		// адрес и query целиком; двойное декодирование — против %252e%252e и т. п.
		$uri = urldecode(urldecode($request->getRequestUri()));

		$userAgent = (string) $request->userAgent();

		$host = $request->getHost();

		return $this->matches([...static::PATH_RULES, ...$this->extra('paths')], $path)
			|| $this->matches([...static::URI_RULES, ...$this->extra('uris')], $uri)
			|| $this->matches([...static::USER_AGENT_RULES, ...$this->extra('user_agents')], $userAgent)
			// обращение по IP вместо домена — перебор адресов, а не переход на сайт
			|| (filter_var($host, FILTER_VALIDATE_IP) && !in_array($host, ['127.0.0.1', '::1'], true))
			// методы, которыми сайт не пользуется (PROPFIND, TRACE, CONNECT…)
			|| !in_array($request->getMethod(), config('bot-guard.allowed_methods', ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']), true)
			// браузеры и поисковые боты всегда шлют User-Agent; без него 404/405 — перебор адресов
			|| ($userAgent === '' && in_array($code, [404, 405], true))
			|| $this->isForgedLivewireUpdate($request, $path)
			|| $this->isBodyExploit($request)
			|| $this->matchesCustomRules($request, $code);
	}

	/**
	 * Запрос к Livewire (/livewire/update, /livewire-<хэш>/update) не от Livewire: его JS-клиент всегда
	 * шлёт заголовок X-Livewire и JSON. Без них — скрипт, повторяющий снятый со страницы запрос
	 * (сам Livewire отвечает на такой запрос 404 в RequireLivewireHeaders, «чтобы не подтверждать
	 * сканеру адрес»). Вошедшие пользователи таких запросов не делают
	 */
	protected function isForgedLivewireUpdate(Request $request, string $path): bool
	{
		return $request->isMethod('POST')
			&& preg_match('~^/livewire(-[^/]+)?/update$~', $path) === 1
			&& (!$request->hasHeader('X-Livewire') || !$request->isJson());
	}

	/**
	 * Нагрузка RCE в теле запроса (BODY_RULES, config bot-guard.rules.bodies) к адресу, у которого нет
	 * маршрута для этого метода (POST / вместо GET /, чужие API). Существующие маршруты — формы сайта,
	 * Livewire, API — не проверяются: в их полях пользователи законно пишут любой текст
	 */
	protected function isBodyExploit(Request $request): bool
	{
		if ($request->isMethod('GET') || $request->isMethod('HEAD')) {
			return false;
		}

		$body = substr((string) $request->getContent() ?: $this->formBody($request), 0, static::BODY_LIMIT);
		$rules = [...static::BODY_RULES, ...$this->extra('bodies')];

		if ($body === '' || (!$this->matches($rules, $body) && !$this->matches($rules, $this->normalizeBody($body)))) {
			return false;
		}

		try {
			return Route::getRoutes()->match($request) === null;
		} catch (Throwable) {
			// NotFoundHttpException / MethodNotAllowedHttpException — маршрута нет
			return true;
		}
	}

	/**
	 * Поля формы строкой name=value&…: у multipart/form-data (так шлёт Server Actions Next.js и проба React2Shell)
	 * PHP разбирает тело сам и сырого тела не отдаёт — без этого проверялась бы пустая строка
	 */
	protected function formBody(Request $request): string
	{
		$pairs = [];
		$walk = function (array $data, string $prefix) use (&$walk, &$pairs): void {
			foreach ($data as $key => $value) {
				$name = $prefix === '' ? (string) $key : $prefix . (array_is_list($data) ? '[]' : "[{$key}]");

				if (is_array($value)) {
					$walk($value, $name);
				} else {
					$pairs[] = $name . '=' . $value;
				}
			}
		};
		$walk($request->request->all(), '');

		return implode('&', $pairs);
	}

	/**
	 * Тело без маскировки: URL-кодирование (%24ACTION%5FREF_0) и экранирование \u005f / \x5f любой глубины
	 * (JSON внутри JSON даёт \\\\u005f) — по два прохода
	 */
	protected function normalizeBody(string $body): string
	{
		for ($i = 0; $i < 2; $i++) {
			$body = urldecode($body);
			$body = preg_replace_callback('~\\\\+u([0-9a-fA-F]{4})~', fn(array $m): string => mb_chr(hexdec($m[1]), 'UTF-8') ?: '', $body) ?? $body;
			$body = preg_replace_callback('~\\\\+x([0-9a-fA-F]{2})~', fn(array $m): string => chr(hexdec($m[1])), $body) ?? $body;
		}

		return $body;
	}

	protected function matches(array $rules, string $subject): bool
	{
		return (bool) preg_match('~' . implode('|', $rules) . '~i', $subject);
	}

	protected function extra(string $key): array
	{
		return array_values(array_filter((array) config("bot-guard.rules.{$key}", [])));
	}

	protected function matchesCustomRules(Request $request, ?int $code): bool
	{
		foreach ($this->extra('custom') as $rule) {
			if (is_a($rule, ScannerRule::class, true) && app($rule)->matches($request, $code)) {
				return true;
			}
		}

		return false;
	}
}
