<?php

namespace DurexKz\BotGuard\Models;

use Carbon\Carbon;
use DurexKz\BotGuard\BotGuard;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Справочник заблокированных IP. Хранится конкретный адрес, а блокируется вся его подсеть (networkOf):
 * запросы из неё middleware BlockScanners отклоняет ответом 404 ещё до сессии, маршрутизации и журнала ошибок.
 * Записи создаёт фильтр сканеров (is_auto) или администратор
 *
 * @property int $id
 * @property string $ip
 * @property string $reason
 * @property bool $is_auto
 * @property ?Carbon $banned_until
 * @property int $hits
 * @property ?Carbon $last_hit_at
 */
class BannedIp extends Model
{
	protected $fillable = [
		'ip',
		'reason',
		'is_auto',
		'banned_until',
		'url',
		'user_agent',
		'hits',
		'last_hit_at',
		'created_by',
	];

	public function getTable(): string
	{
		return config('bot-guard.table', 'banned_ips');
	}

	protected function casts(): array
	{
		return [
			'is_auto' => 'boolean',
			'banned_until' => 'datetime',
			'last_hit_at' => 'datetime',
			'hits' => 'integer',
		];
	}

	protected static function booted(): void
	{
		// список в кэше пересобирается при любом изменении справочника
		static::saved(fn() => static::flushCache());
		static::deleted(fn() => static::flushCache());

		// созданную вручную запись помечаем автором
		static::creating(function (self $ban) {
			if (!$ban->is_auto && $ban->created_by === null && auth()->check()) {
				$ban->created_by = auth()->id();
			}
		});
	}

	public function creator(): BelongsTo
	{
		return $this->belongsTo(BotGuard::userModel(), 'created_by');
	}

	/**
	 * Блокировка действует: бессрочная или срок ещё не истёк
	 */
	public function scopeActive(Builder $query): Builder
	{
		return $query->where(fn(Builder $q) => $q->whereNull('banned_until')->orWhere('banned_until', '>', now()));
	}

	public function isActive(): bool
	{
		return $this->banned_until === null || $this->banned_until->isFuture();
	}

	public static function autoBanHours(): int
	{
		return (int) config('bot-guard.auto_ban_hours', 24);
	}

	/**
	 * Подсеть, в которую блокируется IP: 203.0.113.57 → 203.0.113.0/24, 2001:db8:1:2:3:4:5:6 → 2001:db8:1:2::/64
	 */
	public static function networkOf(string $ip): ?string
	{
		$binary = filter_var($ip, FILTER_VALIDATE_IP) !== false ? @inet_pton($ip) : false;

		if ($binary === false) {
			return null;
		}

		$isV6 = strlen($binary) === 16;
		$prefix = max(0, min($isV6 ? 128 : 32, (int) config($isV6 ? 'bot-guard.ipv6_prefix' : 'bot-guard.ipv4_prefix', $isV6 ? 64 : 24)));

		// обнуляем биты адреса после префикса
		$masked = '';
		foreach (str_split($binary) as $i => $byte) {
			$bits = max(0, min(8, $prefix - $i * 8));
			$masked .= chr(ord($byte) & (0xFF << (8 - $bits)) & 0xFF);
		}

		return inet_ntop($masked) . '/' . $prefix;
	}

	/**
	 * Заблокированный IP из справочника, в подсеть которого попадает $ip, или null.
	 * Проверяется на каждом запросе, поэтому по кэшу, а не по таблице.
	 * Сбой кэша или БД не должен закрывать сайт: тогда считаем, что не заблокирован
	 */
	public static function matchBan(?string $ip): ?string
	{
		$network = blank($ip) ? null : static::networkOf($ip);

		if ($network === null) {
			return null;
		}

		try {
			$bans = Cache::rememberForever(static::cacheKey(), fn() => static::query()
				->active()
				->get(['ip', 'banned_until'])
				->groupBy(fn(self $ban) => static::networkOf($ban->ip) ?? $ban->ip)
				->map(fn($group) => $group->mapWithKeys(fn(self $ban) => [$ban->ip => $ban->banned_until?->getTimestamp()])->all())
				->all());
		} catch (Throwable) {
			return null;
		}

		foreach ($bans[$network] ?? [] as $bannedIp => $until) {
			if ($until === null || $until > time()) {
				return $bannedIp;
			}
		}

		return null;
	}

	/**
	 * Учесть отклонённый запрос из подсети заблокированного IP
	 */
	public static function registerHit(string $bannedIp): void
	{
		try {
			static::query()->where('ip', $bannedIp)->update([
				'hits' => DB::raw('hits + 1'),
				'last_hit_at' => now(),
			]);
		} catch (Throwable) {
			// учёт не должен ломать ответ
		}
	}

	/**
	 * Заблокировать IP (а с ним и подсеть) автоматически — фильтр сканеров. Действующую или ручную
	 * блокировку не трогаем, истёкшую автоматическую продлеваем с новой причиной
	 */
	public static function autoBan(string $ip, string $reason, ?Request $request = null): void
	{
		if (static::networkOf($ip) === null) {
			return;
		}

		try {
			$ban = static::query()->firstOrNew(['ip' => $ip]);

			if ($ban->exists && ($ban->isActive() || !$ban->is_auto)) {
				return;
			}

			$ban->fill([
				'reason' => $reason,
				'is_auto' => true,
				'banned_until' => now()->addHours(static::autoBanHours()),
				'url' => $request ? mb_substr($request->method() . ' ' . $request->fullUrl(), 0, 2000) : null,
				'user_agent' => $request ? (mb_substr((string) $request->userAgent(), 0, 500) ?: null) : null,
				'created_by' => null,
			])->save();
		} catch (Throwable) {
			// блокировка не должна ломать ответ
		}
	}

	/**
	 * Заблокировать вручную (команда bot-guard:ban, панель). $hours = null — бессрочно
	 */
	public static function ban(string $ip, string $reason, ?int $hours = null): static
	{
		$ban = static::query()->firstOrNew(['ip' => $ip]);

		$ban->fill([
			'reason' => $reason,
			'is_auto' => false,
			'banned_until' => $hours ? now()->addHours($hours) : null,
		])->save();

		return $ban;
	}

	public static function cacheKey(): string
	{
		return config('bot-guard.cache_key', 'banned-ips');
	}

	public static function flushCache(): void
	{
		try {
			Cache::forget(static::cacheKey());
		} catch (Throwable) {
		}
	}
}
