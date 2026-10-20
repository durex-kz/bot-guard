<?php

namespace DurexKz\BotGuard\Console;

use DurexKz\BotGuard\BotGuard;
use Illuminate\Console\Command;

class BanCommand extends Command
{
	protected $signature = 'bot-guard:ban
		{ip : IP-адрес; блокируется вся его подсеть}
		{--hours= : На сколько часов; без параметра — бессрочно}
		{--reason=Заблокирован вручную из консоли : Причина}';

	protected $description = 'Заблокировать IP и его подсеть';

	public function handle(): int
	{
		$model = BotGuard::model();
		$ip = (string) $this->argument('ip');

		if ($model::networkOf($ip) === null) {
			$this->error("Некорректный IP: {$ip}");

			return self::FAILURE;
		}

		$hours = $this->option('hours') !== null ? (int) $this->option('hours') : null;
		$ban = $model::ban($ip, (string) $this->option('reason'), $hours);

		$this->info(sprintf(
			'Заблокирована подсеть %s %s',
			$model::networkOf($ip),
			$ban->banned_until ? 'до ' . $ban->banned_until->format('d.m.Y H:i') : 'бессрочно',
		));

		return self::SUCCESS;
	}
}
