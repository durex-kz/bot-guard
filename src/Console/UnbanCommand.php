<?php

namespace DurexKz\BotGuard\Console;

use DurexKz\BotGuard\BotGuard;
use Illuminate\Console\Command;

class UnbanCommand extends Command
{
	protected $signature = 'bot-guard:unban
		{ip : IP-адрес или любой адрес из заблокированной подсети}';

	protected $description = 'Снять блокировку с подсети IP';

	public function handle(): int
	{
		$model = BotGuard::model();
		$network = $model::networkOf((string) $this->argument('ip'));

		if ($network === null) {
			$this->error('Некорректный IP');

			return self::FAILURE;
		}

		$bans = $model::query()->get()->filter(fn($ban) => $model::networkOf($ban->ip) === $network);
		$bans->each->delete();

		$this->info("Снято блокировок в подсети {$network}: {$bans->count()}");

		return self::SUCCESS;
	}
}
