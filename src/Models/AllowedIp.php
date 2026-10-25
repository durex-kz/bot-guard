<?php

namespace DurexKz\BotGuard\Models;

use Carbon\Carbon;
use DurexKz\BotGuard\BotGuard;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Cache;
use Throwable;

/**
 * Белый список: подсеть IP, которую фильтр сканеров не трогает до allowed_until (пусто — навсегда):
 * её запросы не отклоняются, не проверяются правилами сканеров и не ведут к автоблокировке.
 * Обычно запись создаётся из заблокированного IP (fromBan) — тогда хранится ссылка на блокировку
 * и её снимок, а сама блокировка завершается
 *
 * @property int $id
 * @property string $ip
 * @property ?string $network
 * @property ?string $reason
 * @property ?Carbon $allowed_until
 * @property ?int $banned_ip_id
 * @property ?array $banned_snapshot
 */
class AllowedIp extends Model
{
	protected $fillable = [
		'ip',
		'reason',
		'allowed_until',
		'banned_ip_id',
		'banned_snapshot',
		'created_by',
	];

	public function getTable(): string
	{
		return config('bot-guard.allowed_table', 'allowed_ips');
	}

	protected function casts(): array
	{
		return [
			'allowed_until' => 'datetime',
			'banned_snapshot' => 'array',
		];
	}

	protected static function booted(): void
	{
		static::saving(function (self $allowed) {
			$allowed->network = BotGuard::model()::networkOf((string) $allowed->ip);
		});

		static::creating(function (self $allowed) {
			if ($allowed->created_by === null && auth()->check()) {
				$allowed->created_by = auth()->id();
			}
		});

		static::saved(fn() => static::flushCache());
		static::deleted(fn() => static::flushCache());
	}

	public function bannedIp(): BelongsTo
	{
		return $this->belongsTo(BotGuard::model(), 'banned_ip_id');
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

	/**
	 * Сроки на выбор при добавлении (config bot-guard.allow_durations): дни; null — навсегда
	 *
	 * @return array<string, string> ключ — число дней или 'forever'
	 */
	public static function durationOptions(): array
	{
		$options = [];

		foreach ((array) config('bot-guard.allow_durations', [1, 7, 30, null]) as $days) {
			$options[$days === null ? 'forever' : (string) (int) $days] = $days === null ? __('Навсегда') : static::daysLabel((int) $days);
		}

		return $options;
	}

	// 1 день, 2–4 дня, 5+ дней (11–14 — дней); строки переводятся через lang/*.json
	protected static function daysLabel(int $days): string
	{
		$mod10 = $days % 10;
		$mod100 = $days % 100;

		$key = match (true) {
			$mod10 === 1 && $mod100 !== 11 => ':count день',
			$mod10 >= 2 && $mod10 <= 4 && ($mod100 < 12 || $mod100 > 14) => ':count дня',
			default => ':count дней',
		};

		return __($key, ['count' => $days]);
	}

	/**
	 * Срок окончания по выбранному варианту durationOptions(): число дней или 'forever' (null)
	 */
	public static function untilFor(int|string|null $duration): ?Carbon
	{
		return $duration === null || $duration === 'forever' ? null : now()->addDays((int) $duration);
	}

	/**
	 * Перенести заблокированный IP в белый список: запись со ссылкой на блокировку и её снимком,
	 * сама блокировка завершается (остаётся в истории справочника)
	 */
	public static function fromBan(BannedIp $ban, int|string|null $duration, ?string $reason = null): static
	{
		$allowed = static::query()->create([
			'ip' => $ban->ip,
			'reason' => $reason,
			'allowed_until' => static::untilFor($duration),
			'banned_ip_id' => $ban->getKey(),
			'banned_snapshot' => [
				'ip' => $ban->ip,
				'network' => $ban->network ?? BotGuard::model()::networkOf($ban->ip),
				'reason' => $ban->reason,
				'is_auto' => (bool) $ban->is_auto,
				'ban_count' => (int) ($ban->ban_count ?? 0),
				'banned_until' => $ban->banned_until?->toIso8601String(),
				'banned_at' => $ban->created_at?->toIso8601String(),
				'hits' => (int) $ban->hits,
			],
		]);

		if ($ban->isActive()) {
			$ban->forceFill(['banned_until' => now()])->save();
		}

		return $allowed;
	}

	/**
	 * Подсеть $ip в действующем белом списке. Проверяется на каждом запросе — по кэшу.
	 * Сбой кэша или БД — считаем, что не разрешена (фильтр работает как обычно)
	 */
	public static function matchAllow(?string $ip): bool
	{
		$network = blank($ip) ? null : BotGuard::model()::networkOf($ip);

		if ($network === null) {
			return false;
		}

		try {
			$allowed = Cache::rememberForever(static::cacheKey(), fn() => static::query()
				->active()
				->get(['network', 'allowed_until'])
				->groupBy('network')
				->map(fn($group) => $group->map(fn(self $a) => $a->allowed_until?->getTimestamp())->all())
				->all());
		} catch (Throwable) {
			return false;
		}

		foreach ($allowed[$network] ?? [] as $until) {
			if ($until === null || $until > time()) {
				return true;
			}
		}

		return false;
	}

	public static function cacheKey(): string
	{
		return config('bot-guard.allowed_cache_key', 'allowed-ips');
	}

	public static function flushCache(): void
	{
		try {
			Cache::forget(static::cacheKey());
		} catch (Throwable) {
		}
	}
}
