<?php

namespace DurexKz\BotGuard\Console;

use DurexKz\BotGuard\BotGuard;
use Illuminate\Console\Command;

class AllowCountryCommand extends Command
{
	protected $signature = 'bot-guard:allow-country
		{code? : Код страны ISO 3166-1 alpha-2 (KZ, RU…); без параметра — показать список}
		{--days= : На сколько дней; без параметра — навсегда}
		{--reason=Разрешена вручную из консоли : Причина}';

	protected $description = 'Внести страну в белый список стран или показать список (страна размещения сайта добавляется сама)';

	public function handle(): int
	{
		$model = BotGuard::allowedCountryModel();
		$code = strtoupper(trim((string) $this->argument('code')));

		if ($code === '') {
			$model::activeMap(); // добавит страну размещения, если её нет

			$this->table(['Страна', 'Разрешена до', 'Причина'], $model::query()->active()->orderBy('country_code')->get()
				->map(fn($c) => [
					$model::countryName($c->country_code) . ' (' . $c->country_code . ')' . ($c->isHome() ? ' — страна размещения' : ''),
					$c->allowed_until?->format('d.m.Y H:i') ?? 'навсегда',
					$c->reason,
				])->all());

			return self::SUCCESS;
		}

		if (!preg_match('/^[A-Z]{2}$/', $code)) {
			$this->error("Некорректный код страны: {$code}");

			return self::FAILURE;
		}

		$days = $this->option('days') !== null ? (int) $this->option('days') : null;

		$country = $model::query()->create([
			'country_code' => $code,
			'reason' => (string) $this->option('reason'),
			'allowed_until' => $days === null ? null : now()->addDays($days),
		]);

		$this->info(sprintf(
			'%s (%s) в белом списке стран %s',
			$model::countryName($code),
			$code,
			$country->allowed_until ? 'до ' . $country->allowed_until->format('d.m.Y H:i') : 'навсегда',
		));

		return self::SUCCESS;
	}
}
