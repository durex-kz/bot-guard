<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Страна и город IP — определяются один раз при блокировке по локальной базе GeoLite2-City
     * (DurexKz\BotGuard\GeoIp). Существующие записи заполняет bot-guard:geoip-fill
     */
    public function up(): void
    {
        Schema::table(config('bot-guard.table', 'banned_ips'), function (Blueprint $table) {
	        $table->char('country_code', 2)->nullable()->index()->comment('Код страны ISO 3166-1 (GeoLite2)');
	        $table->string('country', 100)->nullable()->comment('Страна (GeoLite2)');
	        $table->string('city', 100)->nullable()->comment('Город (GeoLite2)');
        });
    }

    public function down(): void
    {
        Schema::table(config('bot-guard.table', 'banned_ips'), function (Blueprint $table) {
	        $table->dropIndex(['country_code']);
	        $table->dropColumn(['country_code', 'country', 'city']);
        });
    }
};
