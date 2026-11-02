<?php

namespace DurexKz\BotGuard\Console;

use DurexKz\BotGuard\GeoIp;
use FilesystemIterator;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use MaxMind\Db\Reader;
use PharData;
use RecursiveIteratorIterator;
use Throwable;

/**
 * Скачать свежую базу GeoLite2-City с сайта MaxMind (бесплатная учётная запись: ID и ключ лицензии
 * в MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY). MaxMind обновляет базу дважды в неделю —
 * в приложении: Schedule::command('bot-guard:geoip-update')->weekly()
 */
class GeoIpUpdateCommand extends Command
{
	protected $signature = 'bot-guard:geoip-update {--no-fill : Не заполнять страну и город у записей без них}';

	protected $description = 'Скачать базу MaxMind GeoLite2-City для страны и города заблокированных IP';

	public function handle(GeoIp $geoIp): int
	{
		$accountId = config('bot-guard.geoip.account_id');
		$licenseKey = config('bot-guard.geoip.license_key');

		if (blank($accountId) || blank($licenseKey)) {
			$this->error('Не заданы MAXMIND_ACCOUNT_ID и MAXMIND_LICENSE_KEY (бесплатная регистрация на maxmind.com → GeoLite2)');

			return self::FAILURE;
		}

		$edition = (string) config('bot-guard.geoip.edition', 'GeoLite2-City');
		$target = GeoIp::databasePath();
		$dir = dirname($target);
		$archive = $dir . '/' . $edition . '-' . uniqid() . '.tar.gz';
		$temp = $target . '.' . uniqid() . '.tmp';

		File::ensureDirectoryExists($dir);

		try {
			$response = Http::withBasicAuth((string) $accountId, (string) $licenseKey)
				->timeout(300)
				->sink($archive)
				->get("https://download.maxmind.com/geoip/databases/{$edition}/download", ['suffix' => 'tar.gz']);

			if (!$response->successful()) {
				$this->error("MaxMind ответил {$response->status()}: проверьте ID и ключ лицензии");

				return self::FAILURE;
			}

			// в архиве — каталог GeoLite2-City_ГГГГММДД/ с файлом .mmdb
			$mmdb = null;
			foreach (new RecursiveIteratorIterator(new PharData($archive, FilesystemIterator::SKIP_DOTS)) as $file) {
				if (str_ends_with($file->getFilename(), '.mmdb')) {
					$mmdb = $file->getPathname();
					break;
				}
			}

			if ($mmdb === null || !copy($mmdb, $temp)) {
				$this->error('В архиве MaxMind нет файла .mmdb');

				return self::FAILURE;
			}

			// база читается — только тогда заменяем рабочую
			$metadata = (new Reader($temp))->metadata();
			$geoIp->reset();
			rename($temp, $target);

			$this->info(sprintf('База %s от %s: %s', $metadata->databaseType, date('d.m.Y', $metadata->buildEpoch), $target));
		} catch (Throwable $e) {
			$this->error('Не удалось обновить базу: ' . $e->getMessage());

			return self::FAILURE;
		} finally {
			File::delete([$archive, $temp]);
		}

		if (!$this->option('no-fill')) {
			$this->call('bot-guard:geoip-fill');
		}

		return self::SUCCESS;
	}
}
