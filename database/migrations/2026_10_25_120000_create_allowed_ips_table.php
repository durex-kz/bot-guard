<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Белый список: подсети, которые фильтр сканеров не трогает до allowed_until. Обычно запись
     * создаётся из заблокированного IP (действие «В белый список»): banned_ip_id и снимок блокировки
     * banned_snapshot остаются и после удаления блокировки — видно, откуда взялась запись
     */
    public function up(): void
    {
        Schema::create(config('bot-guard.allowed_table', 'allowed_ips'), function (Blueprint $table) {
	        $table->id();
	        $table->string('ip', 45)->index()->comment('IP; разрешается вся его подсеть (по умолчанию /24, IPv6 — /64)');
	        $table->string('network', 64)->nullable()->index()->comment('Подсеть IP');
	        $table->text('reason')->nullable()->comment('Почему разрешён');
	        $table->timestamp('allowed_until')->nullable()->index()->comment('Разрешён до; пусто — навсегда');
	        $table->unsignedBigInteger('banned_ip_id')->nullable()->index()->comment('Блокировка, из которой создана запись');
	        $table->text('banned_snapshot')->nullable()->comment('Снимок блокировки (JSON): IP, причина, срок, номер повтора');
	        $table->unsignedBigInteger('created_by')->nullable()->comment('Кто добавил; пусто — система');
	        $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists(config('bot-guard.allowed_table', 'allowed_ips'));
    }
};
