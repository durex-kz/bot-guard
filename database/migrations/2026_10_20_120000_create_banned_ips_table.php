<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create(config('bot-guard.table', 'banned_ips'), function (Blueprint $table) {
	        $table->id();
	        $table->string('ip', 45)->unique()->comment('IP сканера; блокируется вся его подсеть (по умолчанию /24, IPv6 — /64)');
	        $table->text('reason')->comment('Причина блокировки');
	        $table->boolean('is_auto')->default(false)->comment('Заблокирован автоматически фильтром сканеров');
	        $table->timestamp('banned_until')->nullable()->index()->comment('Блокировка до; пусто — бессрочно');
	        $table->string('url', 2000)->nullable()->comment('Запрос, после которого IP заблокирован');
	        $table->string('user_agent', 500)->nullable()->comment('User-Agent этого запроса');
	        $table->unsignedInteger('hits')->default(0)->comment('Сколько запросов отклонено после блокировки');
	        $table->timestamp('last_hit_at')->nullable()->comment('Последний отклонённый запрос');
	        $table->unsignedBigInteger('created_by')->nullable()->comment('Кто заблокировал; пусто — система');
	        $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists(config('bot-guard.table', 'banned_ips'));
    }
};
