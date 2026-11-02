<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
	/**
	 * Белый список стран: если в нём есть действующие записи, сайт отвечает только посетителям из этих стран
	 * (страна — по локальной базе GeoLite2). Страна размещения сайта добавляется автоматически на 10 лет
	 */
	public function up(): void
	{
		Schema::create(config('bot-guard.countries.table', 'allowed_countries'), function (Blueprint $table) {
			$table->id();
			$table->char('country_code', 2)->index()->comment('Код страны ISO 3166-1 alpha-2 (KZ, RU…)');
			$table->text('reason')->nullable()->comment('Почему разрешена');
			$table->timestamp('allowed_until')->nullable()->index()->comment('Разрешена до; пусто — навсегда');
			$table->unsignedBigInteger('created_by')->nullable()->comment('Кто добавил; пусто — система');
			$table->timestamps();
		});
	}

	public function down(): void
	{
		Schema::dropIfExists(config('bot-guard.countries.table', 'allowed_countries'));
	}
};
