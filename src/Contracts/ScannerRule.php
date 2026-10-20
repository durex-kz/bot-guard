<?php

namespace DurexKz\BotGuard\Contracts;

use Illuminate\Http\Request;

/**
 * Собственное правило распознавания сканера. Подключается в config/bot-guard.php → rules.custom
 */
interface ScannerRule
{
	/**
	 * @param int|null $code HTTP-код ответа, если он уже известен (при записи в журнал ошибок)
	 */
	public function matches(Request $request, ?int $code = null): bool;
}
