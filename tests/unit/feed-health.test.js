'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert } = require('../test-utils');
const {
  evaluateFeedHealth,
  checkFeedHealth,
  loadFeedHealth,
  MIN_HEALTHY_BASELINE
} = require('../../src/ioc/feed-health.js');

const NOW = '2026-06-07T12:00:00.000Z';
const HEALTHY = MIN_HEALTHY_BASELINE + 100; // comfortably above the floor

async function runFeedHealthTests() {
  console.log('\n=== IOC Feed-Health Alarm Tests (Phase 2c) ===\n');

  // ── pure decision core ──

  test('evaluateFeedHealth: healthy→0 raises a one-shot alarm and marks the feed dark', () => {
    const prev = { OSM: { lastHealthy: HEALTHY, lastHealthyAt: '2026-06-01T00:00:00.000Z', dark: false } };
    const { alarms, nextState } = evaluateFeedHealth({ OSM: 0 }, prev, NOW);
    assert(alarms.length === 1 && alarms[0].feed === 'OSM', 'OSM going dark must alarm');
    assert(alarms[0].lastHealthy === HEALTHY, 'alarm carries the last healthy count');
    assert(nextState.OSM.dark === true, 'feed marked dark');
  });

  test('evaluateFeedHealth: 0→0 (already dark) does NOT re-alarm each cycle', () => {
    const prev = { OSM: { lastHealthy: HEALTHY, lastHealthyAt: NOW, dark: true } };
    const { alarms } = evaluateFeedHealth({ OSM: 0 }, prev, NOW);
    assert(alarms.length === 0, 'a feed that is already dark must stay quiet');
  });

  test('evaluateFeedHealth: healthy→healthy does not alarm and refreshes the baseline', () => {
    const prev = { OSM: { lastHealthy: HEALTHY, lastHealthyAt: '2026-06-01T00:00:00.000Z', dark: false } };
    const { alarms, nextState } = evaluateFeedHealth({ OSM: HEALTHY + 50 }, prev, NOW);
    assert(alarms.length === 0, 'healthy feed must not alarm');
    assert(nextState.OSM.lastHealthy === HEALTHY + 50 && nextState.OSM.lastHealthyAt === NOW, 'baseline refreshed');
  });

  test('evaluateFeedHealth: a brand-new feed at 0 does NOT alarm (no prior healthy baseline)', () => {
    const { alarms, nextState } = evaluateFeedHealth({ NewFeed: 0 }, {}, NOW);
    assert(alarms.length === 0, 'no baseline → no alarm (avoids FP on a never-seen feed)');
    assert(nextState.NewFeed.dark === true, 'still tracked as dark');
  });

  test('evaluateFeedHealth: a feed whose baseline never crossed MIN does NOT alarm at 0', () => {
    const prev = { Tiny: { lastHealthy: MIN_HEALTHY_BASELINE - 1, lastHealthyAt: NOW, dark: false } };
    const { alarms } = evaluateFeedHealth({ Tiny: 0 }, prev, NOW);
    assert(alarms.length === 0, 'sub-threshold baseline is too small/volatile to alarm on');
  });

  test('evaluateFeedHealth: dark→alive emits a recovery and clears the dark flag', () => {
    const prev = { OSM: { lastHealthy: HEALTHY, lastHealthyAt: NOW, dark: true } };
    const { alarms, recoveries, nextState } = evaluateFeedHealth({ OSM: HEALTHY }, prev, NOW);
    assert(alarms.length === 0, 'recovery is not an alarm');
    assert(recoveries.length === 1 && recoveries[0].feed === 'OSM' && recoveries[0].count === HEALTHY, 'recovery reported');
    assert(nextState.OSM.dark === false, 'dark flag cleared');
  });

  test('evaluateFeedHealth: feeds absent from this cycle keep their baseline (carry-forward)', () => {
    const prev = { OSM: { lastHealthy: HEALTHY, lastHealthyAt: NOW, dark: false } };
    const { nextState } = evaluateFeedHealth({ DataDog: HEALTHY }, prev, NOW);
    assert(nextState.OSM && nextState.OSM.lastHealthy === HEALTHY, 'OSM baseline preserved when not reported');
    assert(nextState.DataDog && nextState.DataDog.lastHealthy === HEALTHY, 'new feed recorded');
  });

  // ── checkFeedHealth: persistence + dispatch (best-effort, idempotent) ──

  await asyncTest('checkFeedHealth: alarms once on healthy→dark, persists state, does not re-dispatch while dark', async () => {
    const file = path.join(os.tmpdir(), `feed-health-${Date.now()}.json`);
    const dispatched = [];
    const dispatch = async (payload) => { dispatched.push(payload); };
    try {
      // Cycle 1: OSM healthy → baseline recorded, no alarm.
      let r = await checkFeedHealth({ OSM: HEALTHY, DataDog: HEALTHY }, { file, dispatch });
      assert(r.alarms.length === 0, 'first healthy cycle: no alarm');
      assert(loadFeedHealth(file).OSM.lastHealthy === HEALTHY, 'baseline persisted to disk');

      // Cycle 2: OSM dark → exactly one alarm + one webhook dispatch.
      r = await checkFeedHealth({ OSM: 0, DataDog: HEALTHY }, { file, dispatch });
      assert(r.alarms.length === 1 && r.alarms[0].feed === 'OSM', 'OSM dark alarms');
      assert(dispatched.length === 1, 'webhook dispatched once');
      assert(dispatched[0].embeds[0].fields.some(f => /OSM returned 0/.test(f.name)), 'embed names the dark feed');

      // Cycle 3: OSM still dark → no repeat alarm/dispatch.
      r = await checkFeedHealth({ OSM: 0, DataDog: HEALTHY }, { file, dispatch });
      assert(r.alarms.length === 0, 'still-dark cycle does not re-alarm');
      assert(dispatched.length === 1, 'no duplicate webhook while dark');

      // Cycle 4: OSM recovers → recovery dispatched.
      r = await checkFeedHealth({ OSM: HEALTHY, DataDog: HEALTHY }, { file, dispatch });
      assert(r.recoveries.length === 1, 'recovery reported');
      assert(dispatched.length === 2, 'recovery dispatched');
    } finally { try { fs.unlinkSync(file); } catch {} }
  });

  await asyncTest('checkFeedHealth: never throws on malformed input (best-effort)', async () => {
    const r = await checkFeedHealth(null, { file: path.join(os.tmpdir(), `fh-bad-${Date.now()}.json`), dispatch: async () => {} });
    assert(r && Array.isArray(r.alarms) && r.alarms.length === 0, 'null counts → empty result, no throw');
  });
}

module.exports = { runFeedHealthTests };
