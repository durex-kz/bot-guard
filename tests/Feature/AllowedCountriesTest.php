<?php

use DurexKz\BotGuard\GeoIp;
use DurexKz\BotGuard\Models\AllowedCountry;
use DurexKz\BotGuard\Models\AllowedIp;
use DurexKz\BotGuard\Models\BannedIp;

// тестовая база MaxMind: 81.2.69.142 — Великобритания, 89.160.20.112 — Швеция, 216.160.83.56 — США, 1.1.1.1 — нет в базе
beforeEach(function () {
	config()->set('bot-guard.geoip.database', __DIR__ . '/../Fixtures/GeoIP2-City-Test.mmdb');
	config()->set('bot-guard.countries.home', 'GB');
	app(GeoIp::class)->reset();
	AllowedCountry::flushCache();
});

function fromIp(string $ip): array
{
	return ['REMOTE_ADDR' => $ip];
}

it('adds the home country automatically for 10 years and lets only listed countries in', function () {
	$this->get('/login', fromIp('81.2.69.142'))->assertOk();

	$home = AllowedCountry::sole();
	expect($home->country_code)->toBe('GB')
		->and($home->created_by)->toBeNull()
		->and((int) round(now()->diffInYears($home->allowed_until)))->toBe(10)
		->and($home->isHome())->toBeTrue();

	$this->get('/login', fromIp('89.160.20.112'))
		->assertForbidden()
		->assertSee('обращения из вашей страны (Швеция)', false)
		->assertSee('(SE)', false);

	// страна, которой нет в базе, частный адрес — не ограничиваются
	$this->get('/login', fromIp('1.1.1.1'))->assertOk();
	$this->get('/login', fromIp('192.168.1.10'))->assertOk();

	AllowedCountry::create(['country_code' => 'se', 'reason' => 'Партнёры']);
	$this->get('/login', fromIp('89.160.20.112'))->assertOk();

	// срок истёк — снова закрыта
	AllowedCountry::where('country_code', 'SE')->update(['allowed_until' => now()->subMinute()]);
	AllowedCountry::flushCache();
	$this->get('/login', fromIp('89.160.20.112'))->assertForbidden();
});

it('re-adds the home country when its record is deleted or expired', function () {
	AllowedCountry::activeMap();
	AllowedCountry::sole()->delete();

	expect(AllowedCountry::isAllowed('GB'))->toBeTrue()
		->and(AllowedCountry::isAllowed('SE'))->toBeFalse()
		->and(AllowedCountry::active()->where('country_code', 'GB')->count())->toBe(1);

	AllowedCountry::query()->update(['allowed_until' => now()->subDay()]);
	AllowedCountry::flushCache();
	expect(AllowedCountry::isAllowed('GB'))->toBeTrue()
		->and(AllowedCountry::active()->where('country_code', 'GB')->count())->toBe(1);
});

it('takes the home country from the app timezone when it is not configured', function () {
	config()->set('bot-guard.countries.home', null);

	config()->set('app.timezone', 'Asia/Almaty');
	expect(AllowedCountry::homeCountry())->toBe('KZ');

	config()->set('app.timezone', 'UTC');
	expect(AllowedCountry::homeCountry())->toBeNull()
		->and(AllowedCountry::isAllowed('SE'))->toBeTrue(); // нет страны размещения и записей — ограничения нет
});

it('lets the IP allow list through from any country, and checks countries before bans and scanner rules', function () {
	AllowedIp::create(['ip' => '89.160.20.1', 'reason' => 'Офис в Швеции']);
	$this->get('/login', fromIp('89.160.20.112'))->assertOk();

	// заблокированная подсеть из запрещённой страны получает 403 страны, а не 404 блокировки
	BannedIp::ban('216.160.83.56', 'Вручную');
	$this->get('/login', fromIp('216.160.83.56'))->assertForbidden();

	// сканер из запрещённой страны до правил не доходит и в автоблокировку не попадает
	$this->get('/.env', fromIp('175.16.199.5'))->assertForbidden();
	$this->get('/.env', fromIp('81.2.69.142'))->assertNotFound();
});

it('does not restrict without the GeoLite2 database or when switched off', function () {
	config()->set('bot-guard.geoip.database', '/nonexistent/GeoLite2-City.mmdb');
	app(GeoIp::class)->reset();
	$this->get('/login', fromIp('89.160.20.112'))->assertOk();

	config()->set('bot-guard.geoip.database', __DIR__ . '/../Fixtures/GeoIP2-City-Test.mmdb');
	app(GeoIp::class)->reset();
	config()->set('bot-guard.countries.enabled', false);
	$this->get('/login', fromIp('89.160.20.112'))->assertOk();
});

it('lists and adds countries from the console, with names from intl', function () {
	$this->artisan('bot-guard:allow-country', ['code' => 'se', '--days' => 7])
		->expectsOutputToContain('(SE) в белом списке стран до')
		->assertSuccessful();

	$this->artisan('bot-guard:allow-country')->expectsOutputToContain('страна размещения')->assertSuccessful();
	$this->artisan('bot-guard:allow-country', ['code' => 'xyz'])->assertFailed();

	expect(AllowedCountry::countryName('KZ', 'ru'))->toBe('Казахстан')
		->and(AllowedCountry::countryOptions('ru'))->toHaveKey('KZ')->not->toHaveKey('EU')->not->toHaveKey('ZZ');
});
