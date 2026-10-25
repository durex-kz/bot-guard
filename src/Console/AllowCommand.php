<?php

namespace DurexKz\BotGuard\Console;

use DurexKz\BotGuard\BotGuard;
use Illuminate\Console\Command;

class AllowCommand extends Command
{
	protected $signature = 'bot-guard:allow
		{ip : IP-адрес; разрешается вся его подсеть}
		{--days= : На сколько дней; без параметра — навсегда}
		{--reason=Разрешён вручную из консоли : Причина}';

	protected $description = 'Внести IP и его подсеть в белый список (заблокированный — со ссылкой на блокировку)';

	public function handle(): int
	{
		$model = BotGuard::model();
		$allowedModel = BotGuard::allowedModel();
		$ip = (string) $this->argument('ip');
		$network = $model::networkOf($ip);

		if ($network === null) {
			$this->error("Некорректный IP: {$ip}");

			return self::FAILURE;
		}

		$days = $this->option('days') !== null ? (int) $this->option('days') : null;
		$reason = (string) $this->option('reason');

		// блокировка этой подсети (сначала того же IP) — запись белого списка ссылается на неё
		$ban = $model::query()->where('ip', $ip)->first()
			?? $model::query()->where('network', $network)->active()->latest('id')->first();

		$allowed = $ban
			? $allowedModel::fromBan($ban, $days, $reason)
			: $allowedModel::query()->create(['ip' => $ip, 'reason' => $reason, 'allowed_until' => $allowedModel::untilFor($days)]);

		$this->info(sprintf(
			'Подсеть %s в белом списке %s%s',
			$network,
			$allowed->allowed_until ? 'до ' . $allowed->allowed_until->format('d.m.Y H:i') : 'навсегда',
			$ban ? " (блокировка №{$ban->getKey()} завершена)" : '',
		));

		return self::SUCCESS;
	}
}
