<?php

use DurexKz\BotGuard\Models\BannedIp;
use DurexKz\BotGuard\ScannerDetector;
use DurexKz\ErrorMonitor\Models\ErrorLog;
use Illuminate\Http\Request;

function probe(string $uri, string $userAgent = 'Mozilla/5.0', string $method = 'GET', ?string $host = null): bool
{
	return app(ScannerDetector::class)->isProbe(Request::create(($host ? "http://{$host}" : '') . $uri, $method, server: ['HTTP_USER_AGENT' => $userAgent]));
}

it('computes the blocked subnet of an IP', function () {
	expect(BannedIp::networkOf('203.0.113.57'))->toBe('203.0.113.0/24')
		->and(BannedIp::networkOf('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8:1:2::/64')
		->and(BannedIp::networkOf('not-an-ip'))->toBeNull();

	config()->set('bot-guard.ipv4_prefix', 16);

	expect(BannedIp::networkOf('203.0.113.57'))->toBe('203.0.0.0/16');
});

it('recognizes scanner probes from both projects', function () {
	expect(probe('/phpinfo.php.bak'))->toBeTrue()
		->and(probe('/.env'))->toBeTrue()
		->and(probe('/wp-login.php'))->toBeTrue()
		->and(probe('/blog/?rest_route=/wp/v2/users'))->toBeTrue()                  // «Апельсин»
		->and(probe('/news/games.html?_dispatch_probe=abc'))->toBeTrue()            // QazPress
		->and(probe('/news/games.html', 'Mozilla/5.0 (compatible; seo-health-probe/1.0)'))->toBeTrue()
		->and(probe('/?id=1 union select 1'))->toBeTrue()
		->and(probe('/', 'sqlmap/1.7'))->toBeTrue()
		->and(probe('/', 'Mozilla/5.0', 'PROPFIND'))->toBeTrue()
		->and(probe('/', 'Mozilla/5.0', 'GET', '203.0.113.10'))->toBeTrue()
		->and(probe('/composer.lock'))->toBeTrue()
		->and(probe('/composer.json'))->toBeTrue()
		->and(probe('/vendor/composer/installed.json'))->toBeTrue()
		->and(probe('/package-lock.json'))->toBeTrue()
		// обычные адреса
		->and(probe('/'))->toBeFalse()
		->and(probe('/posts/15'))->toBeFalse()
		->and(probe('/docs/composer-guide'))->toBeFalse()
		->and(probe('/.well-known/assetlinks.json'))->toBeFalse()
		->and(probe('/document/5', 'QR Scanner/2.1'))->toBeFalse()
		->and(probe('/news/games.html', 'Mozilla/5.0 (compatible; Googlebot/2.1)'))->toBeFalse();
});

it('recognizes SQL injection probes without flagging ordinary search queries', function () {
	// перебор из журнала QazPress: ?magazineissue=… на /service/8
	foreach ([
		"/service/8?magazineissue=9' ORDER BY 1-- -",
		'/service/8?magazineissue=9 ORDER BY 1-- -',
		"/service/8?magazineissue=) AND (1664132497=1664132497'",
		"/service/8?magazineissue=9 AND 5978=CONVERT(INT,(SELECT 'fpcwoe'+((SELECT (CASE WHEN (5978=5978) THEN '1' ELSE '0' END)))+'iuklgq'))-- -",
		"/service/8?magazineissue=9' AND 8314=CONVERT(INT,(SELECT 1))-- -",
		'/service/8?magazineissue=' . rawurlencode("9' ORDER BY 1-- -"),
		"/?id=1' AND 1=1-- -",
		"/?id=1') OR ('7'='7",
		'/?id=1 AND CAST(@@version AS INT)',
		'/?q=1 UNION ALL SELECT table_name FROM information_schema.tables',
		"/?id=1';WAITFOR DELAY '0:0:5'--",
	] as $uri) {
		expect(probe($uri))->toBeTrue($uri);
	}

	foreach ([
		'/magazines?q=order by date',
		'/search?q=select from where',
		'/search?q=rock and roll',
		"/search?q=O'Brien and 2 others",
		'/search?q=1 = 1',
		'/posts?sort=-created_at',
		'/service/8?magazineissue=9',
	] as $uri) {
		expect(probe($uri))->toBeFalse($uri);
	}
});

it('supports extra rules from config', function () {
	expect(probe('/old-admin'))->toBeFalse();

	config()->set('bot-guard.rules.paths', ['/old-admin(/|$)']);
	config()->set('bot-guard.rules.user_agents', ['evilbot']);

	expect(probe('/old-admin'))->toBeTrue()
		->and(probe('/', 'EvilBot/2.0'))->toBeTrue();
});

it('answers 404 to a scanner probe and logs it as a scanner', function () {
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])
		->get('/phpinfo.php.bak')
		->assertNotFound();

	expect(ErrorLog::where('ip', '203.0.113.5')->where('is_scanner', true)->whereNotNull('resolved_at')->exists())->toBeTrue()
		->and(BannedIp::where('ip', '203.0.113.5')->exists())->toBeFalse();
});

it('bans the IP after repeated probes and blocks its whole /24', function () {
	foreach (range(1, config('bot-guard.probes_to_ban')) as $i) {
		$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])->get('/.env')->assertNotFound();
	}

	$ban = BannedIp::where('ip', '203.0.113.5')->firstOrFail();

	expect($ban->is_auto)->toBeTrue()
		->and($ban->reason)->toContain('203.0.113.0/24')
		->and($ban->isActive())->toBeTrue();

	// соседний адрес той же /24 получает 404 даже на обычную страницу; в журнал ошибок не пишется
	$logged = ErrorLog::count();

	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.200'])->get('/login')->assertNotFound();

	expect(ErrorLog::count())->toBe($logged)
		->and($ban->fresh()->hits)->toBe(1);

	// другая подсеть не затронута
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.114.5'])->get('/login')->assertOk();
});

it('never bans private addresses', function () {
	foreach (range(1, config('bot-guard.probes_to_ban') + 1) as $i) {
		$this->withServerVariables(['REMOTE_ADDR' => '192.168.1.10'])->get('/.env')->assertNotFound();
	}

	expect(BannedIp::count())->toBe(0);
});

it('does not block after the ban expires', function () {
	BannedIp::create(['ip' => '198.51.100.7', 'reason' => 'test', 'banned_until' => now()->subMinute()]);

	$this->withServerVariables(['REMOTE_ADDR' => '198.51.100.8'])->get('/login')->assertOk();
});

it('lets script clients reach existing API routes', function () {
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])
		->withHeader('User-Agent', 'python-requests/2.32')
		->getJson('/api/magazines/issues')
		->assertUnprocessable(); // дошёл до контроллера: без magazineId — ошибка валидации

	// чужой API тем же клиентом — сканер
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])
		->withHeader('User-Agent', 'python-requests/2.32')
		->get('/api/v1/dags')
		->assertNotFound();
});

it('keeps the health check reachable by IP', function () {
	$this->get('http://10.0.0.5/up')->assertOk();
});

it('can be switched off', function () {
	config()->set('bot-guard.enabled', false);

	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])->get('/.well-known/traffic-advice?x=../../etc/passwd')->assertOk();
});

it('bans and unbans from the console', function () {
	$this->artisan('bot-guard:ban', ['ip' => '198.51.100.7', '--hours' => 2])->assertSuccessful();

	expect(BannedIp::matchBan('198.51.100.99'))->toBe('198.51.100.7');

	$this->artisan('bot-guard:unban', ['ip' => '198.51.100.1'])->assertSuccessful();

	expect(BannedIp::count())->toBe(0)->and(BannedIp::matchBan('198.51.100.99'))->toBeNull();
});

it('lets error-monitor recognize scanners in error logs', function () {
	$request = Request::create('/wp-admin/setup-config.php', server: ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Mozilla/5.0']);

	ErrorLog::register(404, new Exception(), $request);

	expect(ErrorLog::sole())->is_scanner->toBeTrue();
});

it('treats a burst of different 404 pages from one IP as a scanner and bans it', function () {
	config()->set('bot-guard.not_found_burst', 3);

	foreach (['/purchases', '/public', '/announcements', '/lots', '/trades'] as $path) {
		$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->get($path)->assertNotFound();
	}

	// с 3-го адреса — перебор; 3-й, 4-й и 5-й запросы доводят счётчик до probes_to_ban
	expect(BannedIp::where('ip', '203.0.113.9')->value('reason'))->toContain('перебора адресов')
		->and(ErrorLog::where('ip', '203.0.113.9')->count())->toBe(5)
		->and(ErrorLog::where('ip', '203.0.113.9')->where('is_scanner', false)->exists())->toBeFalse();

	// заблокирована вся подсеть
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])->get('/login')->assertNotFound();
});

it('does not count repeated, static, subresource, private or signed-in 404s as a burst', function () {
	config()->set('bot-guard.not_found_burst', 3);

	$get = fn(string $ip, string $path, array $headers = []) => $this->withServerVariables(['REMOTE_ADDR' => $ip])
		->withHeaders($headers)->get($path)->assertNotFound();

	foreach (range(1, 5) as $i) {
		$get('203.0.113.21', '/old-link'); // один и тот же адрес
		$get('203.0.113.22', "/img/photo-{$i}.png"); // битые картинки на странице
		$get('203.0.113.23', "/page-{$i}", ['Sec-Fetch-Dest' => 'image']); // подзапрос браузера
		$get('10.0.0.5', "/page-{$i}"); // частный адрес
		$get('203.0.113.25', "/old-page-{$i}", ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)']); // поисковый робот
	}

	$this->actingAs(new \Illuminate\Auth\GenericUser(['id' => 1]));

	foreach (range(1, 5) as $i) {
		$get('203.0.113.24', "/page-{$i}"); // вошедший пользователь
	}

	expect(BannedIp::count())->toBe(0)
		->and(ErrorLog::where('is_scanner', true)->exists())->toBeFalse();
});

it('can switch the 404 burst rule off', function () {
	config()->set('bot-guard.not_found_burst', 0);

	foreach (range(1, 8) as $i) {
		$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.30'])->get("/page-{$i}")->assertNotFound();
	}

	expect(BannedIp::count())->toBe(0);
});

it('recognizes Livewire update requests that do not come from Livewire', function () {
	$livewire = fn(string $uri, array $headers = []) => app(ScannerDetector::class)->isProbe(
		Request::create($uri, 'POST', server: ['HTTP_USER_AGENT' => 'Mozilla/5.0', ...$headers], content: '{"components":[]}')
	);

	expect($livewire('/livewire-37496913/update'))->toBeTrue()                                   // без X-Livewire
		->and($livewire('/livewire/update', ['CONTENT_TYPE' => 'application/json']))->toBeTrue()   // без X-Livewire
		->and($livewire('/livewire-37496913/update', ['HTTP_X_LIVEWIRE' => '1']))->toBeTrue()      // не JSON
		// настоящий запрос Livewire
		->and($livewire('/livewire-37496913/update', ['HTTP_X_LIVEWIRE' => '1', 'CONTENT_TYPE' => 'application/json']))->toBeFalse()
		->and($livewire('/livewire/update', ['HTTP_X_LIVEWIRE' => '1', 'CONTENT_TYPE' => 'application/json']))->toBeFalse()
		// другие адреса Livewire и похожие страницы
		->and(probe('/livewire-37496913/livewire.js'))->toBeFalse()
		->and(probe('/livewire-37496913/update'))->toBeFalse() // GET — не запрос компонента
		->and($livewire('/news/livewire/update-2026'))->toBeFalse();
});
