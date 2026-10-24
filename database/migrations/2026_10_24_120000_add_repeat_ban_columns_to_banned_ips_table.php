<?php

use DurexKz\BotGuard\BotGuard;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Повторные атаки подсети: срок автоблокировки растёт в auto_ban_multiplier раз с каждым повтором.
     * network — подсеть записи (повтор может прийти с другого IP той же подсети), ban_count — номер
     * автоблокировки подсети
     */
    public function up(): void
    {
        $table = config('bot-guard.table', 'banned_ips');

        Schema::table($table, function (Blueprint $table) {
	        $table->string('network', 64)->nullable()->index()->comment('Подсеть IP (по умолчанию /24, IPv6 — /64)');
	        $table->unsignedInteger('ban_count')->default(0)->comment('Номер автоблокировки подсети: срок растёт с каждым повтором');
        });

        // существующие записи: подсеть по IP, автоблокировки — первые
        $model = BotGuard::model();
        $model::query()->each(function ($ban) use ($model) {
	        $ban->forceFill([
		        'network' => $model::networkOf($ban->ip),
		        'ban_count' => $ban->is_auto ? 1 : 0,
	        ])->saveQuietly();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table(config('bot-guard.table', 'banned_ips'), function (Blueprint $table) {
	        $table->dropIndex(['network']);
	        $table->dropColumn(['network', 'ban_count']);
        });
    }
};
