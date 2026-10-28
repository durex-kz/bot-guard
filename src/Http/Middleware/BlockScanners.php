<?php

namespace DurexKz\BotGuard\Http\Middleware;

use Closure;
use DurexKz\BotGuard\BotGuard;
use DurexKz\BotGuard\ScannerDetector;
use DurexKz\ErrorMonitor\ErrorMonitor;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Throwable;

/**
 * Фильтр запросов сканеров уязвимостей. Ставится в конец глобального стека (после TrustProxies — нужен
 * настоящий IP клиента), до сессии и маршрутизации, поэтому отказ почти ничего не стоит:
 *
 *   ->withMiddleware(function (Middleware $middleware) {
 *       // только свои прокси: с '*' посетитель подставляет себе IP через X-Forwarded-For
 *       $middleware->trustProxies(at: ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']);
 *       $middleware->append(\DurexKz\BotGuard\Http\Middleware\BlockScanners::class);
 *   })
 *
 * - IP из подсети заблокированного адреса (справочник BannedIp) → 404, в журнал ошибок не пишется,
 *   только счётчик hits у записи справочника;
 * - запрос по правилам ScannerDetector → 404 и запись в журнал ошибок (если установлен error-monitor:
 *   is_scanner, сразу решённая); после probes_to_ban таких запросов из одной подсети за
 *   probes_window_minutes минут IP заносится в справочник на auto_ban_hours часов, а с ним и его подсеть;
 * - перебор адресов: not_found_burst разных несуществующих страниц с одного IP за not_found_burst_seconds
 *   секунд — тоже сканер, даже если адреса обычные (/purchases, /lots, /trades): его 404 в журнале
 *   помечаются сканерными, а запросы серии учитываются в автоблокировке
 *
 * Ответ 404, а не 403: сканеру не сообщаем, что его распознали
 */
class BlockScanners
{
	public function __construct(protected ScannerDetector $detector)
	{
	}

	public function handle(Request $request, Closure $next): Response
	{
		if (!config('bot-guard.enabled', true) || $request->is(...config('bot-guard.except', ['up']))) {
			return $next($request);
		}

		$ip = $request->ip();
		$model = BotGuard::model();

		// белый список: подсеть не блокируется и не проверяется правилами сканеров
		if (BotGuard::allowedModel()::matchAllow($ip)) {
			return $next($request);
		}

		if ($bannedIp = $model::matchBan($ip)) {
			$model::registerHit($bannedIp);

			return $this->reject();
		}

		if ($this->isTrustedRoute($request) || !$this->detector->isProbe($request)) {
			$response = $next($request);

			$this->trackNotFound($request, $response);

			return $response;
		}

		$this->logProbe($request);

		$this->countTowardsBan($request);

		return $this->reject();
	}

	/**
	 * Запрос сканера — в счётчик автоблокировки подсети; после probes_to_ban запросов за
	 * probes_window_minutes минут IP и его подсеть блокируются
	 */
	protected function countTowardsBan(Request $request, string $kind = 'запросов сканера'): void
	{
		$ip = $request->ip();
		$model = BotGuard::model();

		// локальные и частные адреса (разработка, тесты, artisan, подделанный X-Forwarded-For) не блокируем
		if (!BotGuard::isPublicIp($ip) || !($network = $model::networkOf($ip))) {
			return;
		}

		$probes = $this->countProbe($network);

		if ($probes >= (int) config('bot-guard.probes_to_ban', 3)) {
			$model::autoBan($ip, sprintf(
				'Фильтр сканеров: %d %s из подсети %s за %d мин. Последний: %s %s%s',
				$probes,
				$kind,
				$network,
				config('bot-guard.probes_window_minutes', 10),
				$request->method(),
				mb_substr($request->getRequestUri(), 0, 500),
				filled($request->userAgent()) ? ' (User-Agent: ' . mb_substr($request->userAgent(), 0, 200) . ')' : ' (без User-Agent)',
			), $request);
		}
	}

	/**
	 * Перебор адресов: not_found_burst разных несуществующих страниц (ответ 404) с одного IP за
	 * not_found_burst_seconds секунд. Сами адреса могут быть обычными словами (/purchases, /lots,
	 * /trades) — правилами по адресу такой перебор не поймать, поэтому смотрим на поведение.
	 * Учитываются только переходы гостей на страницы: статические файлы и подзапросы браузера
	 * (картинки, шрифты, скрипты — Sec-Fetch-Dest не document) не считаются, иначе гость, у которого
	 * на странице несколько битых картинок, попал бы под блокировку
	 */
	protected function trackNotFound(Request $request, Response $response): void
	{
		$limit = (int) config('bot-guard.not_found_burst', 5);
		$ip = $request->ip();

		if ($limit < 1
			|| $response->getStatusCode() !== 404
			|| !BotGuard::isPublicIp($ip)
			|| !in_array($request->getMethod(), ['GET', 'HEAD'], true)
			|| $this->isStaticOrSubresource($request)
			|| $this->isSearchEngine($request)
			|| $this->isSignedIn()) {
			return;
		}

		$paths = $this->rememberNotFound($ip, '/' . ltrim($request->path(), '/'));

		if ($paths < $limit) {
			return;
		}

		// прежние 404 серии в журнале ошибок — сканерные (следующие журнал пометит сам: с этого IP недавно был сканер)
		$this->markScannerSeries($ip);

		$this->countTowardsBan($request, 'запросов перебора адресов');
	}

	/**
	 * Запомнить несуществующий адрес IP в окне not_found_burst_seconds (отсчёт от первого) и вернуть,
	 * сколько разных адресов в окне
	 */
	protected function rememberNotFound(string $ip, string $path): int
	{
		$key = 'bot-guard:not-found:' . $ip;
		$now = now()->getTimestamp();

		try {
			$burst = Cache::get($key);

			if (!is_array($burst) || ($burst['until'] ?? 0) < $now) {
				$burst = ['until' => $now + max(1, (int) config('bot-guard.not_found_burst_seconds', 10)), 'paths' => []];
			}

			$burst['paths'][sha1($path)] = true;

			Cache::put($key, $burst, max(1, $burst['until'] - $now));

			return count($burst['paths']);
		} catch (Throwable) {
			return 0;
		}
	}

	protected function isStaticOrSubresource(Request $request): bool
	{
		$dest = $request->headers->get('Sec-Fetch-Dest');

		return (filled($dest) && !in_array($dest, ['document', 'iframe'], true))
			|| preg_match('~\.(css|js|mjs|map|json|png|jpe?g|gif|svg|webp|avif|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3)$~i', $request->path());
	}

	protected function isSearchEngine(Request $request): bool
	{
		$pattern = (string) config('bot-guard.not_found_burst_except_user_agents', '');

		return $pattern !== '' && preg_match('~' . $pattern . '~i', (string) $request->userAgent()) === 1;
	}

	// вошедший пользователь проверяется без лишнего обращения к сессии: только если он уже определён
	protected function isSignedIn(): bool
	{
		try {
			return app()->bound('auth') && app('auth')->guard()->hasUser();
		} catch (Throwable) {
			return false;
		}
	}

	protected function markScannerSeries(string $ip): void
	{
		if (!config('bot-guard.log_to_error_monitor', true) || !class_exists(ErrorMonitor::class)) {
			return;
		}

		try {
			ErrorMonitor::model()::markScannerIp($ip, now());
		} catch (Throwable) {
			// журнал ошибок не должен ломать ответ
		}
	}

	/**
	 * Запрос сканера — в журнал ошибок (durex-kz/error-monitor), если он установлен
	 */
	protected function logProbe(Request $request): void
	{
		if (config('bot-guard.log_to_error_monitor', true) && class_exists(ErrorMonitor::class)
			&& ErrorMonitor::shouldRecord(404, $request)) {
			ErrorMonitor::record(404, new NotFoundHttpException(), $request);
		}
	}

	/**
	 * Счётчик запросов сканера из подсети в окне probes_window_minutes (отсчёт от первого запроса)
	 */
	protected function countProbe(string $network): int
	{
		$key = 'scanner-probes:' . $network;

		try {
			Cache::add($key, 0, now()->addMinutes((int) config('bot-guard.probes_window_minutes', 10)));

			return (int) Cache::increment($key);
		} catch (Throwable) {
			return 0;
		}
	}

	/**
	 * Запрос к существующему маршруту в trust_existing_routes. Маршрутизатор спрашиваем только для этих
	 * адресов: сканеры перебирают и чужие API (api/v1/dags, api/org…), такие адреса маршрута не найдут
	 * и пойдут под правила
	 */
	protected function isTrustedRoute(Request $request): bool
	{
		$patterns = config('bot-guard.trust_existing_routes', []);

		if (empty($patterns) || !$request->is(...$patterns)) {
			return false;
		}

		try {
			return Route::getRoutes()->match($request) !== null;
		} catch (Throwable) {
			return false;
		}
	}

	protected function reject(): Response
	{
		return response(
			config('bot-guard.response.body', 'Not Found'),
			(int) config('bot-guard.response.status', 404),
			['Content-Type' => 'text/plain; charset=UTF-8'],
		);
	}
}
