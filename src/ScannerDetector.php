<?php

namespace DurexKz\BotGuard;

use DurexKz\BotGuard\Contracts\ScannerRule;
use Illuminate\Http\Request;

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
		. '|composer\.(json|lock)|vendor/composer/installed\.json|package(-lock)?\.json|yarn\.lock)(/|$)',
	];

	/**
	 * Адрес и query: обход каталогов, SQL-инъекции, XSS, Log4Shell, PHP/RCE-нагрузки
	 */
	protected const URI_RULES = [
		'\.\./|\.\.\\\\|/etc/passwd|win\.ini|union[\s/*]+(all[\s/*]+)?select|<script|javascript:',
		'\$\{jndi:|\$\{\$\{|allow_url_include|auto_prepend_file|xdebug_session_start|base64_decode\(',
		'\beval\(|sleep\(\d+\)|benchmark\(|waitfor\s+delay|/bin/(ba)?sh|cmd\.exe|\bwget\s|\bcurl\s',
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
		'python-requests|python-urllib',
		// проверки конкретных уязвимостей называют себя по номеру CVE: cve-2026-63030/1.0, metabase-cve-2026-72898-detect
		'\bcve-\d{4}-\d+',
	];

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
			|| $this->matchesCustomRules($request, $code);
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
