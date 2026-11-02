<?php

namespace DurexKz\BotGuard\Console;

use DurexKz\BotGuard\GeoIp;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use MaxMind\Db\Reader;
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
			if (!$this->extractMmdb($archive, $temp)) {
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

	/**
	 * Достать .mmdb из .tar.gz потоком, кусками по 1 МБ: PharData разворачивает архив (~60 МБ) в память целиком
	 * и упирается в memory_limit. Формат tar: заголовок 512 байт (имя — байты 0–99, префикс пути — 345–499,
	 * размер восьмеричным — 124–135), затем данные, дополненные до кратного 512
	 */
	protected function extractMmdb(string $archive, string $target): bool
	{
		$gz = gzopen($archive, 'rb');

		if ($gz === false) {
			return false;
		}

		try {
			while (strlen($header = $this->readExactly($gz, 512)) === 512 && trim($header, "\0") !== '') {
				$name = rtrim(substr($header, 345, 155), "\0") . '/' . rtrim(substr($header, 0, 100), "\0");
				$size = octdec(trim(substr($header, 124, 12), "\0 "));
				$padded = (int) (ceil($size / 512) * 512);
				$type = $header[156];

				// ._имя — служебная копия атрибутов файла macOS, не база
				if (($type === '0' || $type === "\0") && str_ends_with($name, '.mmdb') && !str_starts_with(basename($name), '._')) {
					$out = fopen($target, 'wb');

					for ($left = $size; $left > 0; $left -= strlen($chunk)) {
						$chunk = $this->readExactly($gz, (int) min(1048576, $left));

						if ($chunk === '') {
							fclose($out);

							return false;
						}

						fwrite($out, $chunk);
					}

					fclose($out);

					return true;
				}

				// пропустить данные записи (каталог, лицензия, README)
				for ($left = $padded; $left > 0; $left -= strlen($chunk)) {
					if (($chunk = $this->readExactly($gz, (int) min(1048576, $left))) === '') {
						return false;
					}
				}
			}
		} finally {
			gzclose($gz);
		}

		return false;
	}

	/**
	 * gzread может вернуть меньше запрошенного — дочитываем до $length или конца архива
	 *
	 * @param resource $gz
	 */
	protected function readExactly($gz, int $length): string
	{
		$data = '';

		while (strlen($data) < $length && !gzeof($gz)) {
			$chunk = gzread($gz, $length - strlen($data));

			if ($chunk === false || $chunk === '') {
				break;
			}

			$data .= $chunk;
		}

		return $data;
	}
}
