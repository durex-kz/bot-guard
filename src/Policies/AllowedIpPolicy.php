<?php

namespace DurexKz\BotGuard\Policies;

use DurexKz\BotGuard\BotGuard;
use Illuminate\Database\Eloquent\Model;

/**
 * Белый список IP ведёт администратор (gate из config bot-guard.admin_gate)
 */
class AllowedIpPolicy
{
	public function viewAny($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function view($user, Model $allowedIp): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function create($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function update($user, Model $allowedIp): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function delete($user, Model $allowedIp): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function deleteAny($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function restore($user, Model $allowedIp): bool
	{
		return false;
	}

	public function forceDelete($user, Model $allowedIp): bool
	{
		return false;
	}
}
