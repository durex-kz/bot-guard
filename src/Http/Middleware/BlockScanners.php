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
 *       $middleware->trustProxies(at: '*');
 *       $middleware->append(\DurexKz\BotGuard\Http\Middleware\BlockScanners::class);
 *   })
 *
 * - IP из подсети заблокированного адреса (справочник BannedIp) → 404, в журнал ошибок не пишется,
 *   только счётчик hits у записи справочника;
 * - запрос по правилам ScannerDetector → 404 и запись в журнал ошибок (если установлен error-monitor:
 *   is_scanner, сразу решённая); после probes_to_ban таких запросов из одной подсети за
 *   probes_window_minutes минут IP заносится в справочник на auto_ban_hours часов, а с ним и его подсеть
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

		if ($bannedIp = $model::matchBan($ip)) {
			$model::registerHit($bannedIp);

			return $this->reject();
		}

		if ($this->isTrustedRoute($request) || !$this->detector->isProbe($request)) {
			return $next($request);
		}

		$this->logProbe($request);

		// локальные и частные адреса (разработка, тесты, artisan, подделанный X-Forwarded-For) не блокируем
		if (BotGuard::isPublicIp($ip) && ($network = $model::networkOf($ip))) {
			$probes = $this->countProbe($network);

			if ($probes >= (int) config('bot-guard.probes_to_ban', 3)) {
				$model::autoBan($ip, sprintf(
					'Фильтр сканеров: %d запросов сканера из подсети %s за %d мин. Последний: %s %s%s',
					$probes,
					$network,
					config('bot-guard.probes_window_minutes', 10),
					$request->method(),
					mb_substr($request->getRequestUri(), 0, 500),
					filled($request->userAgent()) ? ' (User-Agent: ' . mb_substr($request->userAgent(), 0, 200) . ')' : ' (без User-Agent)',
				), $request);
			}
		}

		return $this->reject();
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
