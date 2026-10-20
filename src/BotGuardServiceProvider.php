<?php

namespace DurexKz\BotGuard;

use DurexKz\BotGuard\Console\BanCommand;
use DurexKz\BotGuard\Console\UnbanCommand;
use DurexKz\ErrorMonitor\ErrorMonitor;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class BotGuardServiceProvider extends ServiceProvider
{
	public function register(): void
	{
		$this->mergeConfigFrom(__DIR__ . '/../config/bot-guard.php', 'bot-guard');

		$this->app->singleton(ScannerDetector::class);
	}

	public function boot(): void
	{
		if (config('bot-guard.run_migrations', true)) {
			$this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
		}

		if ($policy = config('bot-guard.policy')) {
			Gate::policy(BotGuard::model(), $policy);
		}

		// журнал ошибок различает запросы сканеров по тем же правилам
		if (class_exists(ErrorMonitor::class)) {
			ErrorMonitor::detectScannersUsing(
				fn(Request $request, ?int $code = null): bool => $this->app->make(ScannerDetector::class)->isProbe($request, $code),
			);
		}

		if ($this->app->runningInConsole()) {
			$this->publishes([
				__DIR__ . '/../config/bot-guard.php' => config_path('bot-guard.php'),
			], 'bot-guard-config');

			$this->publishes([
				__DIR__ . '/../database/migrations' => database_path('migrations'),
			], 'bot-guard-migrations');

			$this->commands([
				BanCommand::class,
				UnbanCommand::class,
			]);
		}
	}
}
