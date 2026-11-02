<?php

use DurexKz\BotGuard\GeoIp;
use DurexKz\BotGuard\Models\BannedIp;
use Illuminate\Support\Facades\Http;

// тестовая база MaxMind (github.com/maxmind/MaxMind-DB, test-data, MIT): 81.2.69.142 — Лондон, 89.160.20.112 — Швеция (город только по-английски)
function useTestGeoDatabase(): void
{
	config()->set('bot-guard.geoip.database', __DIR__ . '/../Fixtures/GeoIP2-City-Test.mmdb');
	app(GeoIp::class)->reset();
}

it('looks up country and city in the local GeoLite2 database, preferring Russian names', function () {
	useTestGeoDatabase();
	$geoIp = app(GeoIp::class);

	expect($geoIp->lookup('81.2.69.142'))->toBe(['country_code' => 'GB', 'country' => 'Великобритания', 'city' => 'Лондон'])
		->and($geoIp->lookup('89.160.20.112'))->toBe(['country_code' => 'SE', 'country' => 'Швеция', 'city' => 'Linköping'])
		->and($geoIp->lookup('1.1.1.1'))->toBeNull()          // нет в базе
		->and($geoIp->lookup('not-an-ip'))->toBeNull();

	config()->set('bot-guard.geoip.locales', ['en']);
	expect($geoIp->lookup('81.2.69.142')['country'])->toBe('United Kingdom');
});

it('stores the location once when an IP is banned, and recomputes it when the IP changes', function () {
	useTestGeoDatabase();

	BannedIp::autoBan('81.2.69.142', 'Сканер');
	$ban = BannedIp::where('ip', '81.2.69.142')->firstOrFail();

	expect($ban->only(['country_code', 'country', 'city']))->toBe(['country_code' => 'GB', 'country' => 'Великобритания', 'city' => 'Лондон'])
		->and($ban->location())->toBe('Великобритания, Лондон');

	$ban->update(['ip' => '175.16.199.1']);
	expect($ban->fresh()->location())->toBe('Китай, Чанчунь');

	// ручная блокировка тоже
	expect(BannedIp::ban('216.160.83.56', 'Вручную')->country_code)->toBe('US');
});

it('bans as usual without the database, and bot-guard:geoip-fill fills the location later', function () {
	config()->set('bot-guard.geoip.database', '/nonexistent/GeoLite2-City.mmdb');
	app(GeoIp::class)->reset();

	BannedIp::autoBan('81.2.69.142', 'Сканер');
	$ban = BannedIp::where('ip', '81.2.69.142')->firstOrFail();

	expect($ban->country_code)->toBeNull()
		->and(BannedIp::matchBan('81.2.69.10'))->toBe('81.2.69.142');

	$this->artisan('bot-guard:geoip-fill')->assertFailed();

	useTestGeoDatabase();
	BannedIp::ban('1.1.1.1', 'Нет в базе');
	$this->artisan('bot-guard:geoip-fill')->expectsOutputToContain('Определено место: 1 из 2')->assertSuccessful();

	expect($ban->fresh()->city)->toBe('Лондон');
});

it('makes a flag emoji from a country code', function () {
	expect(BannedIp::flag('KZ'))->toBe('🇰🇿')
		->and(BannedIp::flag('gb'))->toBe('🇬🇧')
		->and(BannedIp::flag(null))->toBeNull()
		->and(BannedIp::flag('XYZ'))->toBeNull();
});

it('downloads the database from MaxMind and replaces the old one only if the new one is readable', function () {
	$target = sys_get_temp_dir() . '/bot-guard-geoip-' . uniqid() . '/GeoLite2-City.mmdb';
	config()->set('bot-guard.geoip.database', $target);

	$this->artisan('bot-guard:geoip-update')->expectsOutputToContain('MAXMIND_LICENSE_KEY')->assertFailed();

	config()->set('bot-guard.geoip.account_id', '123');
	config()->set('bot-guard.geoip.license_key', 'test-key');

	// архив как у MaxMind: каталог GeoLite2-City_ГГГГММДД/ с файлом .mmdb
	$tar = sys_get_temp_dir() . '/bot-guard-' . uniqid() . '.tar';
	$phar = new PharData($tar);
	$phar->addFile(__DIR__ . '/../Fixtures/GeoIP2-City-Test.mmdb', 'GeoLite2-City_20261031/GeoLite2-City.mmdb');
	$phar->compress(Phar::GZ);
	$archive = file_get_contents($tar . '.gz');

	Http::fake(['download.maxmind.com/*' => Http::sequence()->push('Unauthorized', 401)->push($archive)]);

	$this->artisan('bot-guard:geoip-update')->expectsOutputToContain('401')->assertFailed();
	expect(file_exists($target))->toBeFalse();

	BannedIp::query()->insert(['ip' => '81.2.69.142', 'reason' => 'до базы', 'is_auto' => true, 'hits' => 0, 'ban_count' => 1]);

	$this->artisan('bot-guard:geoip-update')->expectsOutputToContain('GeoIP2-City')->assertSuccessful();

	expect(file_exists($target))->toBeTrue()
		->and(BannedIp::where('ip', '81.2.69.142')->value('city'))->toBe('Лондон');   // заполнено после скачивания

	Http::assertSent(fn($request) => $request->hasHeader('Authorization', 'Basic ' . base64_encode('123:test-key')));

	@unlink($target);
	@unlink($tar);
	@unlink($tar . '.gz');
});
