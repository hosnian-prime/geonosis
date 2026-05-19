// k6 load test: authorize + token endpoint throughput.
//
// Target: >= 5000 req/s on 4 vCPU (v0.1.x done criteria).
//
// Usage:
//   k6 run tests/load/authorize-token.js --env BASE_URL=http://localhost:8080
//
// Prerequisites:
//   - Geonosis running with quickstart bootstrap (realm "master" or seeded realm)
//   - A public client "load-test" registered with redirect_uri http://localhost:9999/cb
//   - A test user "loaduser" with password "LoadTest123!"
//
// Seed with:
//   tests/load/seed-load-realm.sh http://localhost:8080

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';

const BASE = __ENV.BASE_URL || 'http://localhost:8080';
const REALM = __ENV.REALM || 'loadtest';

const authorizeLatency = new Trend('authorize_latency', true);
const tokenLatency = new Trend('token_latency', true);
const errorRate = new Rate('error_rate');

export const options = {
  scenarios: {
    authorize_ramp: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      preAllocatedVUs: 200,
      maxVUs: 500,
      stages: [
        { duration: '30s', target: 1000 },
        { duration: '60s', target: 5000 },
        { duration: '30s', target: 5000 },
        { duration: '30s', target: 0 },
      ],
    },
  },
  thresholds: {
    'authorize_latency': ['p(95)<200', 'p(99)<500'],
    'token_latency': ['p(95)<200', 'p(99)<500'],
    'error_rate': ['rate<0.01'],
  },
};

function generateCodeVerifier() {
  const bytes = crypto.randomBytes(32);
  return encoding.b64encode(bytes, 'rawurl').replace(/=/g, '');
}

function generateCodeChallenge(verifier) {
  const hash = crypto.sha256(verifier, 'binary');
  return encoding.b64encode(hash, 'rawurl').replace(/=/g, '');
}

export default function () {
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const state = `s_${__VU}_${__ITER}`;
  const nonce = `n_${__VU}_${__ITER}`;

  // Step 1: /authorize — expect redirect to login form (302) or login page (200).
  const authUrl = `${BASE}/realms/${REALM}/protocol/openid-connect/auth` +
    `?response_type=code` +
    `&client_id=load-test` +
    `&redirect_uri=${encodeURIComponent('http://localhost:9999/cb')}` +
    `&scope=openid` +
    `&nonce=${nonce}` +
    `&code_challenge=${challenge}` +
    `&code_challenge_method=S256` +
    `&state=${state}`;

  const authResp = http.get(authUrl, { redirects: 0 });
  authorizeLatency.add(authResp.timings.duration);

  const authOk = authResp.status === 200 || authResp.status === 302;
  check(authResp, { 'authorize status ok': () => authOk });
  errorRate.add(!authOk);

  if (!authOk) return;

  // Step 2: Submit login form (password grant via form post).
  // Extract flow_state_id from response body if 200.
  if (authResp.status === 200) {
    const match = authResp.body.match(/name="flow_state_id"\s+value="([^"]+)"/);
    if (!match) {
      errorRate.add(true);
      return;
    }
    const flowStateId = match[1];

    const loginResp = http.post(
      `${BASE}/realms/${REALM}/login-actions/authenticate`,
      {
        flow_state_id: flowStateId,
        username: 'loaduser',
        password: 'LoadTest123!',
      },
      { redirects: 0 }
    );
    tokenLatency.add(loginResp.timings.duration);

    const loginOk = loginResp.status === 302;
    check(loginResp, { 'login redirect': () => loginOk });
    errorRate.add(!loginOk);
  }
}

export function handleSummary(data) {
  const report = {
    timestamp: new Date().toISOString(),
    scenarios: data.metrics,
    thresholds: data.thresholds,
  };
  return {
    'tests/load/report.json': JSON.stringify(report, null, 2),
    stdout: textSummary(data, { indent: '  ', enableColors: true }),
  };
}

function textSummary(data) {
  return JSON.stringify({
    authorize_p50: data.metrics.authorize_latency?.values?.['p(50)'],
    authorize_p95: data.metrics.authorize_latency?.values?.['p(95)'],
    authorize_p99: data.metrics.authorize_latency?.values?.['p(99)'],
    token_p50: data.metrics.token_latency?.values?.['p(50)'],
    token_p95: data.metrics.token_latency?.values?.['p(95)'],
    token_p99: data.metrics.token_latency?.values?.['p(99)'],
    error_rate: data.metrics.error_rate?.values?.rate,
  }, null, 2);
}
