const assert = require('node:assert/strict');
const test = require('node:test');
const { waveDelay, saveFailureArtifacts } = require('./browser-nat.cjs');

test('failed-page diagnostics retain errors without aborting later browser work', async () => {
  const page = {
    screenshot: async () => { throw new Error('screenshot timeout with private-value'); },
    content: async () => { throw new Error('page is navigating with private-value'); },
  };
  const errors = await saveFailureArtifacts(page, 'unused-test-directory', 'failed-page',
    value => value.replaceAll('private-value', '[REDACTED]'));
  assert.deepEqual(errors, {
    screenshot: 'screenshot timeout with [REDACTED]',
    html: 'page is navigating with [REDACTED]',
  });
});

test('browser waves recover delay against the original schedule', () => {
  const epoch = 1000;
  const intervalMs = 15000;
  const durations = [15000, 5000, 5000, 5000];
  let now = epoch + 5000; // Initial uploads are part of the observation period.
  const starts = [];
  for (let wave = 0; wave < durations.length; wave++) {
    now += waveDelay(epoch, intervalMs, wave, now);
    starts.push(now - epoch);
    now += durations[wave];
  }
  assert.deepEqual(starts, [5000, 20000, 30000, 45000]);
  assert.equal(now - epoch, 50000);
});

test('an overloaded wave retains lateness and runs every scheduled wave', () => {
  let now = 0;
  const delays = [];
  for (let wave = 0; wave < 3; wave++) {
    const delay = waveDelay(0, 15000, wave, now);
    assert.equal(delay, 0);
    now += delay;
    delays.push(now - wave * 15000);
    now += 20000;
  }
  assert.deepEqual(delays, [0, 5000, 10000]);
  assert.equal(now, 60000);
});
