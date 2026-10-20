<?php

namespace DurexKz\BotGuard\Policies;

use DurexKz\BotGuard\BotGuard;
use Illuminate\Database\Eloquent\Model;

/**
 * Справочник заблокированных IP ведёт администратор (gate из config bot-guard.admin_gate)
 */
class BannedIpPolicy
{
	public function viewAny($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function view($user, Model $bannedIp): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function create($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function update($user, Model $bannedIp): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function delete($user, Model $bannedIp): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function deleteAny($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function restore($user, Model $bannedIp): bool
	{
		return false;
	}

	public function forceDelete($user, Model $bannedIp): bool
	{
		return false;
	}
}
