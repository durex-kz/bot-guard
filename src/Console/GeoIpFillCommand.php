<?php

namespace DurexKz\BotGuard\Console;

use DurexKz\BotGuard\BotGuard;
use DurexKz\BotGuard\GeoIp;
use Illuminate\Console\Command;

class GeoIpFillCommand extends Command
{
	protected $signature = 'bot-guard:geoip-fill {--all : Определить заново и у записей, где страна уже есть}';

	protected $description = 'Заполнить страну и город заблокированных IP по базе GeoLite2-City';

	public function handle(GeoIp $geoIp): int
	{
		if (!$geoIp->available()) {
			$this->error('Нет базы ' . GeoIp::databasePath() . ' — скачайте: php artisan bot-guard:geoip-update');

			return self::FAILURE;
		}

		$found = $total = 0;

		BotGuard::model()::query()
			->when(!$this->option('all'), fn($query) => $query->whereNull('country_code'))
			->chunkById(500, function ($bans) use (&$found, &$total) {
				foreach ($bans as $ban) {
					$total++;
					$found += (int) $ban->fillGeo();
					// без событий: страна не влияет на кэш блокировок
					$ban->saveQuietly();
				}
			});

		$this->info("Определено место: {$found} из {$total}");

		return self::SUCCESS;
	}
}
