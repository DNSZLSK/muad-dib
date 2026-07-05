const { test, asyncTest, assert } = require('../test-utils');

/**
 * Burst pre-alert Discord toggle (src/monitor/webhook.js `burstPreAlertWebhookEnabled`
 * + `sendBurstPreAlert`).
 *
 * Context (2026-07): the BURST PRE-ALERT heads-up fired ~700×/day and was
 * anti-correlated with real kills/incidents — pure #alerts noise. The fix mutes ONLY
 * the Discord POST for this alert type (default off, opt back in with
 * MUADDIB_BURST_PREALERT_WEBHOOK=1). Everything else at the queue.js call site — the
 * `[MONITOR] BURST PRE-ALERT` console.log, the `stats.burstPreAlerts` counter (daily
 * summary), and the enqueue of the burst versions — is unchanged.
 *
 * These tests spy the SHARED transport (`src/webhook.js` -> integrations/webhook) by
 * swapping its `sendWebhook` for a recorder, then FRESH-require src/monitor/webhook.js
 * so its `const { sendWebhook } = require('../webhook.js')` binds to the recorder. This
 * needs no network (the real sendWebhook does DNS + https.request) and no change to any
 * sibling sender — the recorder captures whichever alert type routes through it. The
 * fresh-require + env-save/restore pattern mirrors tests/unit/http-limiter.test.js.
 */

const TRANSPORT_PATH = require.resolve('../../src/webhook.js');            // shim -> src/integrations/webhook.js
const MONITOR_WEBHOOK_PATH = require.resolve('../../src/monitor/webhook.js');
const ENV_KEYS = ['MUADDIB_WEBHOOK_URL', 'MUADDIB_BURST_PREALERT_WEBHOOK'];
const DISCORD_URL = 'https://discord.com/api/webhooks/123456/abcdef';

// Spy the shared transport + fresh-load monitor/webhook so it binds the spy. Only the
// two env keys above are touched (set from `env`, or deleted for a clean slate).
function setup(env = {}) {
  const savedEnv = {};
  for (const k of ENV_KEYS) {
    savedEnv[k] = process.env[k];
    if (Object.prototype.hasOwnProperty.call(env, k) && env[k] !== undefined) process.env[k] = env[k];
    else delete process.env[k];
  }

  const transport = require(TRANSPORT_PATH);
  const origSend = transport.sendWebhook;
  const calls = [];
  transport.sendWebhook = async (url, payload, options) => { calls.push({ url, payload, options }); };

  delete require.cache[MONITOR_WEBHOOK_PATH];
  const webhook = require(MONITOR_WEBHOOK_PATH);

  const restore = () => {
    transport.sendWebhook = origSend;
    delete require.cache[MONITOR_WEBHOOK_PATH];        // next requirer rebinds the real sendWebhook
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
  };
  return { webhook, calls, restore };
}

async function runBurstPreAlertWebhookTests() {
  await asyncTest('BURST-WEBHOOK: suppressed by default — console.log + stat fire, NO Discord POST', async () => {
    // URL is PRESENT on purpose: proves the new gate (not the pre-existing !url guard)
    // is what suppresses the send.
    const { webhook, calls, restore } = setup({ MUADDIB_WEBHOOK_URL: DISCORD_URL });
    const logs = [];
    const origLog = console.log;
    const stats = {};
    try {
      console.log = (...a) => { logs.push(a.join(' ')); };
      // Faithful replica of the queue.js:2020-2027 emission trio (stat -> log -> send):
      stats.burstPreAlerts = (stats.burstPreAlerts || 0) + 1;
      console.log(`[MONITOR] BURST PRE-ALERT: evil-burst-pkg — 50 versions in the recent window`);
      await webhook.sendBurstPreAlert('evil-burst-pkg', 50, 'npm');
    } finally {
      console.log = origLog;
      restore();
    }
    assert(stats.burstPreAlerts === 1, `stat counter must still increment (got ${stats.burstPreAlerts})`);
    assert(logs.some(l => l.includes('BURST PRE-ALERT: evil-burst-pkg')),
      'the [MONITOR] BURST PRE-ALERT console.log must still fire');
    assert(calls.length === 0, `Discord POST must be suppressed by default (got ${calls.length} webhook call(s))`);
  });

  await asyncTest('BURST-WEBHOOK: MUADDIB_BURST_PREALERT_WEBHOOK=1 re-enables the Discord POST', async () => {
    const { webhook, calls, restore } = setup({ MUADDIB_WEBHOOK_URL: DISCORD_URL, MUADDIB_BURST_PREALERT_WEBHOOK: '1' });
    try {
      await webhook.sendBurstPreAlert('evil-burst-pkg', 50, 'npm');
    } finally {
      restore();
    }
    assert(calls.length === 1, `enabled -> exactly one Discord POST (got ${calls.length})`);
    const blob = JSON.stringify(calls[0].payload);
    assert(blob.includes('BURST PRE-ALERT'), 'the POST payload must be the burst embed');
    assert(blob.includes('evil-burst-pkg'), 'the POST payload must reference the bursting package');
    assert(calls[0].options && calls[0].options.rawPayload === true, 'burst embed is sent as a rawPayload');
  });

  await asyncTest('BURST-WEBHOOK: non-regression — another alert type (campaign) still POSTs while burst is muted', async () => {
    // Burst disabled (flag unset), URL present. A sibling alert type that routes through
    // the SAME shared sendWebhook must still fire — the gate is scoped to burst only.
    const { webhook, calls, restore } = setup({ MUADDIB_WEBHOOK_URL: DISCORD_URL });
    try {
      await webhook.sendBurstPreAlert('evil-burst-pkg', 50, 'npm');        // muted
      await webhook.sendCampaignPreAlert('other-campaign-pkg', 'did-1234', 'npm'); // must still send
    } finally {
      restore();
    }
    assert(calls.length === 1, `burst muted + campaign sent -> exactly 1 POST (got ${calls.length})`);
    const blob = JSON.stringify(calls[0].payload);
    assert(blob.includes('other-campaign-pkg'), 'the single POST must be the campaign alert');
    assert(blob.includes('CAMPAIGN PRE-ALERT'), 'the single POST must be the campaign embed');
    assert(!blob.includes('evil-burst-pkg'), 'the burst alert must NOT have been sent');
  });

  test('BURST-WEBHOOK: burstPreAlertWebhookEnabled parses the env flag (default off; 1/true/yes/on = on)', () => {
    const { webhook, restore } = setup({});   // clean slate: flag unset
    const set = (v) => { if (v === undefined) delete process.env.MUADDIB_BURST_PREALERT_WEBHOOK; else process.env.MUADDIB_BURST_PREALERT_WEBHOOK = v; };
    try {
      set(undefined); assert(webhook.burstPreAlertWebhookEnabled() === false, 'unset -> off (default)');
      set('');        assert(webhook.burstPreAlertWebhookEnabled() === false, 'empty -> off');
      set('0');       assert(webhook.burstPreAlertWebhookEnabled() === false, '"0" -> off');
      set('false');   assert(webhook.burstPreAlertWebhookEnabled() === false, '"false" -> off');
      set('1');       assert(webhook.burstPreAlertWebhookEnabled() === true,  '"1" -> on');
      set('true');    assert(webhook.burstPreAlertWebhookEnabled() === true,  '"true" -> on');
      set('YES');     assert(webhook.burstPreAlertWebhookEnabled() === true,  '"YES" -> on (case-insensitive)');
      set(' on ');    assert(webhook.burstPreAlertWebhookEnabled() === true,  '" on " -> on (trimmed)');
    } finally {
      restore();
    }
  });
}

module.exports = { runBurstPreAlertWebhookTests };
