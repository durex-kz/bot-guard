<?php

use DurexKz\BotGuard\Models\AllowedIp;
use DurexKz\BotGuard\Models\BannedIp;
use DurexKz\BotGuard\ScannerDetector;
use DurexKz\ErrorMonitor\Models\ErrorLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

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
		->and(probe('/mcp', 'Mozilla/5.0', 'POST'))->toBeTrue()                     // поиск MCP-серверов
		->and(probe('/sse'))->toBeTrue()
		->and(probe('/', 'python-httpx/0.28.1'))->toBeTrue()
		->and(probe('/', 'Python/3.12 aiohttp/3.9.5'))->toBeTrue()
		->and(probe('/docs/mcp-guide'))->toBeFalse()
		->and(probe('/posts/sse-events'))->toBeFalse()
		->and(probe('/secrets.json'))->toBeTrue()
		->and(probe('/credentials.json'))->toBeTrue()
		->and(probe('/appsettings.Production.json'))->toBeTrue()
		->and(probe('/service-account.json'))->toBeTrue()
		// исходники и настройки других платформ, служебные адреса Next.js (QazPress, 29.10)
		->and(probe('/config.properties'))->toBeTrue()
		->and(probe('/src/main/resources/application.properties'))->toBeTrue()
		->and(probe('/config/settings/base.py'))->toBeTrue()
		->and(probe('/config/initializers/devise.rb'))->toBeTrue()
		->and(probe('/config/credentials.yml.enc'))->toBeTrue()
		->and(probe('/Dockerfile'))->toBeTrue()
		->and(probe('/web.Release.config'))->toBeTrue()
		->and(probe('/README.md'))->toBeTrue()
		->and(probe('/tsconfig.app.json'))->toBeTrue()
		->and(probe('/Properties/launchSettings.json'))->toBeTrue()
		->and(probe('/env.json'))->toBeTrue()
		->and(probe('/ecosystem.config.js'))->toBeTrue()
		->and(probe('/js/config.js'))->toBeTrue()
		->and(probe('/src/environments/environment.prod.ts'))->toBeTrue()
		->and(probe('/config/aws.json'))->toBeTrue()
		->and(probe('/src/config/settings.ts'))->toBeTrue()
		->and(probe('/conf/logback.xml'))->toBeTrue()
		->and(probe('/_next', 'Mozilla/5.0', 'POST'))->toBeTrue()
		->and(probe('/__nextjs_action', 'Mozilla/5.0', 'POST'))->toBeTrue()
		->and(probe('/_rsc', 'Mozilla/5.0', 'POST'))->toBeTrue()
		->and(probe('/RSC/R/sxbl1eyy3gmdzap.txt', 'Mozilla/5.0', 'POST'))->toBeTrue()
		->and(probe('/_all_dbs'))->toBeTrue()                                        // CouchDB
		->and(probe('/_cluster/health'))->toBeTrue()                                 // Elasticsearch
		->and(probe('/_cat/indices'))->toBeTrue()
		->and(probe('/', 'nosql-domain-extractor/2.0'))->toBeTrue()
		->and(probe('/news/cluster-health'))->toBeFalse()
		->and(probe('/livewire-f9fcf158/js/settings.js'))->toBeFalse()
		->and(probe('/build/assets/app-4f2a.js'))->toBeFalse()
		->and(probe('/js/app.js'))->toBeFalse()
		->and(probe('/news/python-for-beginners'))->toBeFalse()
		->and(probe('/manual/config'))->toBeFalse()
		// обычные адреса
		->and(probe('/'))->toBeFalse()
		->and(probe('/posts/15'))->toBeFalse()
		->and(probe('/docs/composer-guide'))->toBeFalse()
		->and(probe('/news/secrets-of-success'))->toBeFalse()
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

it('recognizes an RCE payload in the body of a request without a route, but not in real forms', function () {
	// проба React Server Components / Next.js («React2Shell») — POST / с подменой прототипа и child_process
	$payload = '["{\\"_response\\":{\\"_chunks\\":\\"$Q2\\",\\"_formData\\":{\\"get\\":\\"$1:constructor:constructor\\"},'
		. '\\"_prefix\\":\\"var res=process.mainModule.require(\'child_process\').execSync(\'echo 1\')\\"},\\"then\\":\\"$1:__proto__:then\\"}"]';
	$post = fn(string $uri, string $body, string $userAgent = 'Mozilla/5.0') => app(ScannerDetector::class)->isProbe(
		Request::create($uri, 'POST', server: ['HTTP_USER_AGENT' => $userAgent, 'CONTENT_TYPE' => 'text/plain'], content: $body),
	);

	Route::post('/articles', fn() => 'saved');

	expect($post('/', $payload))->toBeTrue()                                                     // POST на адрес только для GET
		->and($post('/unknown-api', 'x=require("child_process")'))->toBeTrue()
		->and($post('/articles', 'Пример: require("child_process").execSync("ls")'))->toBeFalse()   // своя форма — любой текст
		->and($post('/', 'обычный текст'))->toBeFalse()
		// проверочная проба без нагрузки (QazPress, 29.10): 1={} 0=["$1:aa:aa"]
		->and($post('/', '{"1":"{}","0":"[\\"$1:aa:aa\\"]"}'))->toBeTrue()
		->and($post('/', '1=%7B%7D&0=%5B%22%241%3Aaa%3Aaa%22%5D'))->toBeTrue()
		->and($post('/articles', '["$1:aa:aa"]'))->toBeFalse()
		// Androxgh0st и клоны (QazPress, 29.10): POST / 0x[]=ridho
		->and($post('/', '0x%5B%5D=ridho'))->toBeTrue()
		->and($post('/', '0x[]=androxgh0st'))->toBeTrue()
		->and($post('/', 'color=0x[]=1'))->toBeFalse()
		->and(probe('/', 'fasthttp'))->toBeTrue();

	// по HTTP: 404 и пометка сканера в журнале
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_USER_AGENT' => 'Mozilla/5.0'])
		->call('POST', '/', content: $payload)
		->assertNotFound();
	expect(ErrorLog::where('ip', '203.0.113.5')->where('is_scanner', true)->exists())->toBeTrue();
});

it('recognizes obfuscated React2Shell probes from the wild, but not the same text in a real form', function () {
	// тела настоящих проб из журнала QazPress: \u005f-экранирование, Buffer через переворот строки, base64,
	// поля Server Action Next.js ($ACTION_REF_0, $ACTION_0:0), двоичные поля-заглушки, браузерный User-Agent
	$bodies = array_map('base64_decode', json_decode(file_get_contents(__DIR__ . '/../Fixtures/react2shell-bodies.json'), true));
	$post = fn(string $uri, string $body) => app(ScannerDetector::class)->isProbe(Request::create($uri, 'POST', server: [
		'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 Safari/537.36',
		'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
	], content: $body));

	Route::post('/articles', fn() => 'saved');

	expect($bodies)->toHaveCount(7);
	foreach ($bodies as $i => $body) {
		expect($post('/', $body))->toBeTrue("проба №{$i}");
	}

	// тот же текст в существующей форме (статья о React/Next.js) — не проба
	expect($post('/articles', $bodies[5]))->toBeFalse()
		->and($post('/', 'text=' . rawurlencode('Обычный текст о $ACTION в документации')))->toBeFalse();
});

it('recognizes React2Shell probes sent as multipart/form-data, where PHP gives no raw body', function () {
	// QazPress, 30.10: те же пробы multipart-формой — getContent() пуст, поля уже разобраны в $request->request
	$multipart = fn(string $uri, array $fields) => app(ScannerDetector::class)->isProbe(Request::create($uri, 'POST', $fields, server: [
		'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/146.0.0.0 Safari/537.36',
		'CONTENT_TYPE' => 'multipart/form-data; boundary=x',
	]));

	Route::post('/articles', fn() => 'saved');

	$fields = [
		'data412' => null,
		'$ACTION_REF_tqCwgB7' => 'x',
		'$ACTION_tqCwgB7:0' => '{"id":"553f55e6b3d59c55f9c74950d20040563e16e286","bound":"$@1"}',
		'$ACTION_tqCwgB7:1' => '{"\\u0073\\u0074\\u0061\\u0074\\u0075\\u0073":"\\u0072\\u0065\\u0073\\u006f\\u006c\\u0076\\u0065\\u0064\\u005f\\u006d\\u006f\\u0064\\u0065\\u006c"}',
	];

	expect($multipart('/', $fields))->toBeTrue()
		->and($multipart('/', ['%24ACTION%5FREF%5F0' => 'x', '%24ACTION%5F0%3A0' => '{"bound":"$@1"}']))->toBeTrue()
		->and($multipart('/', ['0' => '{"then":"$1:\\u005f\\u005fproto\\u005f\\u005f:then","reason":-1}']))->toBeTrue()
		->and($multipart('/', ['0x' => ['androxgh0st']]))->toBeTrue()
		->and($multipart('/articles', $fields))->toBeFalse()                    // своя форма — любой текст
		->and($multipart('/', ['name' => 'Иван', 'text' => 'обычный текст']))->toBeFalse();
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

it('multiplies the ban for every repeated attack from the same subnet', function () {
	$attack = function (string $ip) {
		foreach (range(1, config('bot-guard.probes_to_ban')) as $i) {
			$this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/.env')->assertNotFound();
		}
	};
	$hoursOf = fn(string $ip) => (int) round(now()->diffInHours(BannedIp::where('ip', $ip)->firstOrFail()->banned_until));

	$attack('203.0.113.5');
	expect($hoursOf('203.0.113.5'))->toBe(24)
		->and(BannedIp::where('ip', '203.0.113.5')->value('ban_count'))->toBe(1)
		->and(BannedIp::where('ip', '203.0.113.5')->value('network'))->toBe('203.0.113.0/24');

	// блокировка истекла — подсеть атакует снова, уже с другого IP: срок × 2
	$this->travel(25)->hours();
	$attack('203.0.113.77');
	$second = BannedIp::where('ip', '203.0.113.77')->firstOrFail();
	expect($second->ban_count)->toBe(2)
		->and($hoursOf('203.0.113.77'))->toBe(24 * 2)
		->and($second->reason)->toContain('Повторная атака подсети: блокировка №2 на 2 дн.');

	// третий раз — тот же первый IP: × 2 ещё раз
	$this->travel(24 * 2 + 1)->hours();
	$attack('203.0.113.5');
	expect(BannedIp::where('ip', '203.0.113.5')->value('ban_count'))->toBe(3)
		->and($hoursOf('203.0.113.5'))->toBe(24 * 2 * 2);

	// подсеть вернулась позже окна повтора (24 ч после окончания блокировки) — счёт начинается заново
	$this->travel(24 * 2 * 2 + 25)->hours();
	$attack('203.0.113.9');
	expect(BannedIp::where('ip', '203.0.113.9')->value('ban_count'))->toBe(1)
		->and($hoursOf('203.0.113.9'))->toBe(24);

	// а в пределах окна — снова повтор: № 2, × 2
	$this->travel(24 + 23)->hours();
	$attack('203.0.113.10');
	expect(BannedIp::where('ip', '203.0.113.10')->value('ban_count'))->toBe(2)
		->and($hoursOf('203.0.113.10'))->toBe(48);

	// другая подсеть начинает с обычного срока
	$attack('198.51.100.9');
	expect($hoursOf('198.51.100.9'))->toBe(24);

	// снятие блокировки подсети сбрасывает счёт повторов
	$this->artisan('bot-guard:unban', ['ip' => '203.0.113.1'])->assertSuccessful();
	$attack('203.0.113.5');
	expect(BannedIp::where('ip', '203.0.113.5')->value('ban_count'))->toBe(1)
		->and($hoursOf('203.0.113.5'))->toBe(24);
});

it('counts a late return as a repeat when the window is turned off', function () {
	config()->set('bot-guard.auto_ban_repeat_window_hours', null);
	BannedIp::create(['ip' => '203.0.113.5', 'reason' => 'old', 'is_auto' => true, 'ban_count' => 3, 'banned_until' => now()->subYear()]);

	expect(BannedIp::autoBanCount('203.0.113.0/24'))->toBe(3);

	config()->set('bot-guard.auto_ban_repeat_window_hours', 24);
	expect(BannedIp::autoBanCount('203.0.113.0/24'))->toBe(0);
});

it('caps the repeated ban and allows turning growth off', function () {
	config()->set('bot-guard.auto_ban_max_hours', 1000);
	expect(BannedIp::autoBanHoursFor(1))->toBe(24)
		->and(BannedIp::autoBanHoursFor(2))->toBe(48)
		->and(BannedIp::autoBanHoursFor(3))->toBe(96)
		->and(BannedIp::autoBanHoursFor(6))->toBe(768)
		->and(BannedIp::autoBanHoursFor(7))->toBe(1000)
		->and(BannedIp::autoBanHoursFor(50))->toBe(1000);

	config()->set('bot-guard.auto_ban_multiplier', 1);
	expect(BannedIp::autoBanHoursFor(5))->toBe(24);
});

it('lets an allowed subnet through and links the allow entry to the ban', function () {
	foreach (range(1, config('bot-guard.probes_to_ban')) as $i) {
		$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])->get('/.env')->assertNotFound();
	}
	$ban = BannedIp::where('ip', '203.0.113.5')->firstOrFail();
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.200'])->get('/login')->assertNotFound();

	$allowed = AllowedIp::fromBan($ban, 7, 'Ложное срабатывание: офис за общим IP');

	// ссылка на блокировку и её снимок; блокировка завершена, но осталась в справочнике
	expect($allowed->banned_ip_id)->toBe($ban->id)
		->and($allowed->network)->toBe('203.0.113.0/24')
		->and($allowed->banned_snapshot['reason'])->toBe($ban->reason)
		->and($allowed->banned_snapshot['ip'])->toBe('203.0.113.5')
		->and((int) round(now()->diffInDays($allowed->allowed_until)))->toBe(7)
		->and($allowed->bannedIp->is($ban))->toBeTrue()
		->and($ban->fresh()->isActive())->toBeFalse();

	// вся подсеть проходит: и обычные страницы, и то, что считалось бы пробой, без новой блокировки
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.200'])->get('/login')->assertOk();
	foreach (range(1, config('bot-guard.probes_to_ban') + 1) as $i) {
		$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])->get('/.env');
	}
	expect(BannedIp::where('network', '203.0.113.0/24')->active()->exists())->toBeFalse();

	// снимок остаётся, даже если блокировку удалили (bot-guard:unban)
	$ban->delete();
	expect($allowed->fresh()->banned_snapshot['reason'])->toBe($allowed->banned_snapshot['reason'])
		->and($allowed->fresh()->banned_ip_id)->toBe($ban->id);

	// срок вышел — фильтр снова работает
	$this->travel(8)->days();
	$this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])->get('/.env')->assertNotFound();
});

it('offers allow durations and allows from the console', function () {
	expect(AllowedIp::durationOptions())->toBe(['1' => '1 день', '7' => '7 дней', '30' => '30 дней', 'forever' => 'Навсегда'])
		->and(AllowedIp::untilFor('forever'))->toBeNull()
		->and(AllowedIp::untilFor(null))->toBeNull()
		->and((int) round(now()->diffInDays(AllowedIp::untilFor(30))))->toBe(30);

	$ban = BannedIp::ban('198.51.100.7', 'вручную', 24);
	$this->artisan('bot-guard:allow', ['ip' => '198.51.100.7', '--days' => 1])->assertSuccessful();

	$allowed = AllowedIp::sole();
	expect($allowed->banned_ip_id)->toBe($ban->id)
		->and($ban->fresh()->isActive())->toBeFalse()
		->and(AllowedIp::matchAllow('198.51.100.250'))->toBeTrue();

	// без блокировки — просто запись, навсегда
	$this->artisan('bot-guard:allow', ['ip' => '192.0.2.10'])->assertSuccessful();
	expect(AllowedIp::where('ip', '192.0.2.10')->value('banned_ip_id'))->toBeNull()
		->and(AllowedIp::where('ip', '192.0.2.10')->first()->allowed_until)->toBeNull();
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
