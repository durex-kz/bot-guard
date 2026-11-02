<?php

namespace DurexKz\BotGuard\Models;

use Carbon\Carbon;
use DateTimeZone;
use DurexKz\BotGuard\BotGuard;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Cache;
use Locale;
use ResourceBundle;
use Throwable;

/**
 * Белый список стран. Пока в нём есть действующие записи, сайт отвечает только посетителям из этих стран,
 * остальным — 403 (страна IP — по локальной базе GeoLite2, см. GeoIp). Страна размещения сайта
 * (config bot-guard.countries.home, по умолчанию — страна часового пояса приложения) разрешена всегда:
 * если действующей записи о ней нет, она добавляется автоматически на home_years лет (по умолчанию 10)
 *
 * @property int $id
 * @property string $country_code
 * @property ?string $reason
 * @property ?Carbon $allowed_until
 * @property ?int $created_by
 */
class AllowedCountry extends Model
{
	protected $fillable = [
		'country_code',
		'reason',
		'allowed_until',
		'created_by',
	];

	// коды ICU, которые не являются странами
	protected const NOT_COUNTRIES = ['EU', 'EZ', 'UN', 'QO', 'XA', 'XB', 'ZZ'];

	public function getTable(): string
	{
		return config('bot-guard.countries.table', 'allowed_countries');
	}

	protected function casts(): array
	{
		return [
			'allowed_until' => 'datetime',
		];
	}

	protected static function booted(): void
	{
		static::saving(function (self $country) {
			$country->country_code = strtoupper(trim((string) $country->country_code));
		});

		static::creating(function (self $country) {
			if ($country->created_by === null && auth()->check()) {
				$country->created_by = auth()->id();
			}
		});

		static::saved(fn() => static::flushCache());
		static::deleted(fn() => static::flushCache());
	}

	public function creator(): BelongsTo
	{
		return $this->belongsTo(BotGuard::userModel(), 'created_by');
	}

	public function scopeActive(Builder $query): Builder
	{
		return $query->where(fn(Builder $q) => $q->whereNull('allowed_until')->orWhere('allowed_until', '>', now()));
	}

	public function isActive(): bool
	{
		return $this->allowed_until === null || $this->allowed_until->isFuture();
	}

	public function isHome(): bool
	{
		return $this->country_code === static::homeCountry();
	}

	/**
	 * Страна размещения сайта: config bot-guard.countries.home или страна часового пояса приложения
	 * (Asia/Almaty → KZ). UTC и другие пояса без страны — null, автоматической записи нет
	 */
	public static function homeCountry(): ?string
	{
		$home = config('bot-guard.countries.home');

		if (blank($home)) {
			try {
				$home = (new DateTimeZone((string) config('app.timezone', 'UTC')))->getLocation()['country_code'] ?? null;
			} catch (Throwable) {
				$home = null;
			}
		}

		$home = strtoupper(trim((string) $home));

		return preg_match('/^[A-Z]{2}$/', $home) ? $home : null;
	}

	/**
	 * Нет действующей записи о стране размещения — добавить её на home_years лет
	 */
	public static function ensureHomeCountry(): ?static
	{
		$home = static::homeCountry();

		if ($home === null || static::query()->active()->where('country_code', $home)->exists()) {
			return null;
		}

		$country = new static([
			'country_code' => $home,
			'reason' => 'Страна размещения сайта: добавлена автоматически',
			'allowed_until' => now()->addYears((int) config('bot-guard.countries.home_years', 10)),
		]);

		// система, а не вошедший пользователь; кэш сбрасывает вызывающий
		$country->saveQuietly();

		return $country;
	}

	/**
	 * Действующие записи: код страны => сроки окончания (null — навсегда). По кэшу — проверяется на каждом запросе;
	 * при первой загрузке (и если срок страны размещения истёк) добавляется страна размещения
	 *
	 * @return array<string, array<int, ?int>>
	 */
	public static function activeMap(): array
	{
		$map = static::cachedMap();
		$home = static::homeCountry();

		if ($home !== null && !static::activeIn($map, $home)) {
			static::ensureHomeCountry();
			static::flushCache();
			$map = static::cachedMap();
		}

		return $map;
	}

	protected static function cachedMap(): array
	{
		return Cache::rememberForever(static::cacheKey(), function (): array {
			static::ensureHomeCountry();

			return static::query()
				->active()
				->get(['country_code', 'allowed_until'])
				->groupBy('country_code')
				->map(fn($group) => $group->map(fn(self $c) => $c->allowed_until?->getTimestamp())->values()->all())
				->all();
		});
	}

	protected static function activeIn(array $map, string $code): bool
	{
		foreach ($map[$code] ?? [] as $until) {
			if ($until === null || $until > time()) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Есть действующие записи — значит, действует ограничение по странам
	 */
	public static function restricts(array $map): bool
	{
		foreach (array_keys($map) as $code) {
			if (static::activeIn($map, (string) $code)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Страна разрешена. Неизвестная страна, пустой список, сбой кэша или БД — разрешена:
	 * фильтр по странам не должен закрыть сайт из-за собственной ошибки
	 */
	public static function isAllowed(?string $code): bool
	{
		if (blank($code)) {
			return true;
		}

		try {
			$map = static::activeMap();
		} catch (Throwable) {
			return true;
		}

		return !static::restricts($map) || static::activeIn($map, strtoupper($code));
	}

	/**
	 * Название страны на языке приложения (intl); без intl — код
	 */
	public static function countryName(?string $code, ?string $locale = null): ?string
	{
		if (blank($code)) {
			return null;
		}

		$code = strtoupper($code);

		if (!class_exists(Locale::class)) {
			return $code;
		}

		$name = Locale::getDisplayRegion('-' . $code, $locale ?? app()->getLocale());

		return filled($name) && $name !== $code ? $name : $code;
	}

	/**
	 * Все страны для выбора: код => «Название (KZ)», по алфавиту названий
	 *
	 * @return array<string, string>
	 */
	public static function countryOptions(?string $locale = null): array
	{
		$locale ??= app()->getLocale();
		$codes = [];

		try {
			$bundle = class_exists(ResourceBundle::class) ? ResourceBundle::create('en', 'ICUDATA-region') : null;

			foreach ($bundle['Countries'] ?? [] as $code => $name) {
				if (is_string($code) && preg_match('/^[A-Z]{2}$/', $code) && !in_array($code, static::NOT_COUNTRIES, true)) {
					$codes[] = $code;
				}
			}
		} catch (Throwable) {
		}

		$options = [];

		foreach ($codes as $code) {
			$options[$code] = static::countryName($code, $locale) . ' (' . $code . ')';
		}

		if (class_exists(\Collator::class)) {
			(new \Collator($locale))->asort($options);
		} else {
			asort($options);
		}

		return $options;
	}

	public static function cacheKey(): string
	{
		return config('bot-guard.countries.cache_key', 'allowed-countries');
	}

	public static function flushCache(): void
	{
		try {
			Cache::forget(static::cacheKey());
		} catch (Throwable) {
		}
	}
}
