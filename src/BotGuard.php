<?php

namespace DurexKz\BotGuard;

use DurexKz\BotGuard\Models\AllowedIp;
use DurexKz\BotGuard\Models\BannedIp;
use Illuminate\Support\Facades\Gate;

class BotGuard
{
	/**
	 * @return class-string<BannedIp>
	 */
	public static function model(): string
	{
		return config('bot-guard.model', BannedIp::class);
	}

	/**
	 * @return class-string<AllowedIp>
	 */
	public static function allowedModel(): string
	{
		return config('bot-guard.allowed_model', AllowedIp::class);
	}

	/**
	 * @return class-string<\Illuminate\Database\Eloquent\Model>
	 */
	public static function userModel(): string
	{
		return config('bot-guard.user_model') ?: config('auth.providers.users.model', 'App\\Models\\User');
	}

	/**
	 * Публичный адрес. Частные и служебные (127.0.0.1, ::1, 10/8, 172.16/12, 192.168/16…) не блокируем:
	 * это разработка, тесты, artisan, а сканеры подставляют их в X-Forwarded-For, чтобы сойти
	 * за внутренний запрос (иначе блокируется 172.16.0.0/24 или 192.168.1.0/24)
	 */
	public static function isPublicIp(?string $ip): bool
	{
		return filled($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
	}

	/**
	 * Пользователь — администратор справочника (gate из config bot-guard.admin_gate)
	 */
	public static function isAdmin($user): bool
	{
		$gate = config('bot-guard.admin_gate');

		return $user !== null && filled($gate) && Gate::has($gate) && Gate::forUser($user)->allows($gate);
	}
}
