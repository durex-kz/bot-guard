<?php

namespace DurexKz\BotGuard\Tests;

use DurexKz\BotGuard\BotGuardServiceProvider;
use DurexKz\BotGuard\Http\Middleware\BlockScanners;
use DurexKz\BotGuard\Models\BannedIp;
use DurexKz\ErrorMonitor\ErrorMonitor;
use DurexKz\ErrorMonitor\ErrorMonitorServiceProvider;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
	use RefreshDatabase;

	protected function getPackageProviders($app): array
	{
		return [ErrorMonitorServiceProvider::class, BotGuardServiceProvider::class];
	}

	protected function defineEnvironment($app): void
	{
		$app['config']->set('database.default', 'testing');
		$app['config']->set('cache.default', 'array');
		$app['config']->set('error-monitor.log_in_tests', true);

		$app->make(Kernel::class)->pushMiddleware(BlockScanners::class);

		// журнал ошибок подключается к обработчику исключений, как в bootstrap/app.php приложения
		ErrorMonitor::handle(new Exceptions($app->make(ExceptionHandler::class)));
	}

	protected function defineRoutes($router): void
	{
		$router->get('/up', fn() => 'ok');
		$router->get('/login', fn() => 'login');
		$router->get('/.well-known/traffic-advice', fn() => '[]');
		$router->get('/api/magazines/issues', fn(Request $request) => $request->validate(['magazineId' => 'required']));
	}

	protected function setUp(): void
	{
		parent::setUp();

		BannedIp::flushCache();
	}
}
