<?php

namespace DurexKz\BotGuard;

use MaxMind\Db\Reader;
use Throwable;

/**
 * Страна и город IP по локальной базе MaxMind GeoLite2-City (файл .mmdb, config bot-guard.geoip.database).
 * Поиск — доли миллисекунды, без обращения к сети. Нет базы или адреса в ней — null:
 * блокировка от этого не зависит
 */
class GeoIp
{
	protected ?Reader $reader = null;

	protected ?string $openedPath = null;

	/**
	 * @return array{country_code: ?string, country: ?string, city: ?string}|null
	 */
	public function lookup(?string $ip): ?array
	{
		if (blank($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false || ($reader = $this->reader()) === null) {
			return null;
		}

		try {
			$record = $reader->get($ip);
		} catch (Throwable) {
			return null;
		}

		if (!is_array($record)) {
			return null;
		}

		$geo = [
			'country_code' => $this->limit($record['country']['iso_code'] ?? $record['registered_country']['iso_code'] ?? null, 2),
			'country' => $this->limit($this->name($record['country']['names'] ?? $record['registered_country']['names'] ?? []), 100),
			'city' => $this->limit($this->name($record['city']['names'] ?? []), 100),
		];

		return array_filter($geo) === [] ? null : $geo;
	}

	/**
	 * База на месте — можно определять
	 */
	public function available(): bool
	{
		return $this->reader() !== null;
	}

	public static function databasePath(): string
	{
		return (string) (config('bot-guard.geoip.database') ?: storage_path('app/geoip/GeoLite2-City.mmdb'));
	}

	/**
	 * Закрыть файл: после обновления базы следующий поиск откроет новый
	 */
	public function reset(): void
	{
		try {
			$this->reader?->close();
		} catch (Throwable) {
		}

		$this->reader = null;
		$this->openedPath = null;
	}

	protected function reader(): ?Reader
	{
		$path = static::databasePath();

		if ($this->reader !== null && $this->openedPath === $path) {
			return $this->reader;
		}

		$this->reset();

		if (!config('bot-guard.geoip.enabled', true) || !is_file($path)) {
			return null;
		}

		try {
			$this->reader = new Reader($path);
			$this->openedPath = $path;
		} catch (Throwable) {
			return null;
		}

		return $this->reader;
	}

	// название на первом из языков config bot-guard.geoip.locales, которое есть в базе
	protected function name(array $names): ?string
	{
		foreach ((array) config('bot-guard.geoip.locales', ['ru', 'en']) as $locale) {
			if (filled($names[$locale] ?? null)) {
				return $names[$locale];
			}
		}

		return null;
	}

	protected function limit(?string $value, int $length): ?string
	{
		return blank($value) ? null : mb_substr($value, 0, $length);
	}
}
