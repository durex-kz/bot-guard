<?php

namespace DurexKz\BotGuard\Policies;

use DurexKz\BotGuard\BotGuard;
use Illuminate\Database\Eloquent\Model;

/**
 * Белый список стран ведёт администратор (gate из config bot-guard.admin_gate)
 */
class AllowedCountryPolicy
{
	public function viewAny($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function view($user, Model $allowedCountry): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function create($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function update($user, Model $allowedCountry): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function delete($user, Model $allowedCountry): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function deleteAny($user): bool
	{
		return BotGuard::isAdmin($user);
	}

	public function restore($user, Model $allowedCountry): bool
	{
		return false;
	}

	public function forceDelete($user, Model $allowedCountry): bool
	{
		return false;
	}
}
