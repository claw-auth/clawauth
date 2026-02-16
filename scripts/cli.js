#!/usr/bin/env node
import nacl from 'tweetnacl';
import util from 'tweetnacl-util';
import keytar from 'keytar';
import { Command } from 'commander';

const {
  decodeBase64,
  decodeUTF8,
  encodeBase64,
  encodeUTF8
} = util;

const WORKER_URL = 'https://auth.clawauth.app';
const DEFAULT_SCOPE = process.env.CLAWAUTH_SCOPE || '';
const POLL_INTERVAL_MS = Number(process.env.CLAWAUTH_POLL_INTERVAL_MS || 2000);
const POLL_TIMEOUT_MS = Number(process.env.CLAWAUTH_POLL_TIMEOUT_MS || 300000);
const KEYCHAIN_SERVICE = process.env.CLAWAUTH_KEYCHAIN_SERVICE || 'clawauth';
const KEYCHAIN_ACCOUNT_OVERRIDE = process.env.CLAWAUTH_KEYCHAIN_ACCOUNT || '';
const LEGACY_KEYCHAIN_ACCOUNT = 'tokens:default';
const SESSION_SERVICE = process.env.CLAWAUTH_SESSION_SERVICE || 'clawauth:sessions';
const DEFAULT_TTL_SECONDS = Number(process.env.CLAWAUTH_TTL_SECONDS || 3600);

const MANUAL_TEXT = `
clawauth manual
===============

Purpose
-------
clawauth is an async OAuth CLI for agent workflows.
It lets an agent start auth, send a short link to a user, continue other work,
and later check/claim credentials without blocking a shell process.

Core model
----------
1) Start session:
   clawauth login start <provider> [--ttl 3600]

2) Send shortAuthUrl to user.

3) Check progress later:
   clawauth login status <sessionId>
   clawauth sessions

4) Claim when completed:
   clawauth login claim <sessionId>

5) Use stored token later:
   clawauth token list
   clawauth token get <provider>
   clawauth token env <provider>
   eval "$(clawauth token env <provider>)"

Notes
-----
- 'wait' is optional blocking convenience: clawauth login wait <sessionId>
- Tokens are stored in system keychain.
- Session crypto material is stored locally in keychain until claimed/deleted.
- Default service endpoint is: https://auth.clawauth.app
`;

function toBase64Url(bytes) {
  return encodeBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomNonce() {
  return toBase64Url(nacl.randomBytes(16));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function decryptBlob(blob, boxSecretKeyB64) {
  const boxSecretKey = decodeBase64(boxSecretKeyB64);
  const nonce = decodeBase64(blob.nonce);
  const ciphertext = decodeBase64(blob.ciphertext);
  const ephPub = decodeBase64(blob.ephemeralPublicKey);

  const opened = nacl.box.open(ciphertext, nonce, ephPub, boxSecretKey);
  if (!opened) {
    throw new Error('Unable to decrypt blob');
  }

  return JSON.parse(encodeUTF8(opened));
}

function keychainAccountForProvider(provider) {
  if (KEYCHAIN_ACCOUNT_OVERRIDE) {
    return KEYCHAIN_ACCOUNT_OVERRIDE;
  }
  return `${provider}:default`;
}

async function saveSessionMaterial(sessionId, material) {
  await keytar.setPassword(SESSION_SERVICE, sessionId, JSON.stringify(material));
}

async function loadSessionMaterial(sessionId) {
  const raw = await keytar.getPassword(SESSION_SERVICE, sessionId);
  if (!raw) {
    return null;
  }
  return JSON.parse(raw);
}

async function deleteSessionMaterial(sessionId) {
  await keytar.deletePassword(SESSION_SERVICE, sessionId);
}

async function listSessionMaterials() {
  const credentials = await keytar.findCredentials(SESSION_SERVICE);
  const sessions = [];
  for (const item of credentials) {
    try {
      const material = JSON.parse(item.password);
      sessions.push({ sessionId: item.account, ...material });
    } catch {
      sessions.push({ sessionId: item.account, provider: 'unknown', parseError: true });
    }
  }
  return sessions;
}

async function loadStoredTokenByAccount(account) {
  const raw = await keytar.getPassword(KEYCHAIN_SERVICE, account);
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw);
  } catch {
    return { refresh_token: raw, provider: 'unknown_legacy' };
  }
}

async function saveRefreshToken(provider, tokenData) {
  const refreshToken = tokenData?.refresh_token;
  if (!refreshToken) {
    return false;
  }

  const payload = JSON.stringify({
    provider,
    refresh_token: refreshToken,
    access_token: tokenData.access_token || null,
    token_type: tokenData.token_type || null,
    saved_at: new Date().toISOString()
  });

  await keytar.setPassword(KEYCHAIN_SERVICE, keychainAccountForProvider(provider), payload);
  return true;
}

async function listStoredTokens() {
  const credentials = await keytar.findCredentials(KEYCHAIN_SERVICE);
  const tokens = [];

  for (const item of credentials) {
    if (KEYCHAIN_ACCOUNT_OVERRIDE) {
      if (item.account !== KEYCHAIN_ACCOUNT_OVERRIDE) continue;
    } else if (item.account !== LEGACY_KEYCHAIN_ACCOUNT && !item.account.endsWith(':default')) {
      continue;
    }

    try {
      const parsed = JSON.parse(item.password);
      if (parsed.refresh_token || parsed.access_token) {
        tokens.push({
          account: item.account,
          provider: parsed.provider || item.account.replace(/:default$/, ''),
          ...parsed
        });
      }
    } catch {
      tokens.push({
        account: item.account,
        provider: item.account.replace(/:default$/, ''),
        refresh_token: item.password
      });
    }
  }

  return tokens;
}

async function resolveTokenRecord(provider) {
  if (provider) {
    const account = keychainAccountForProvider(provider);
    const token = await loadStoredTokenByAccount(account);
    if (token) return { account, token: { provider, ...token } };

    if (!KEYCHAIN_ACCOUNT_OVERRIDE) {
      const legacy = await loadStoredTokenByAccount(LEGACY_KEYCHAIN_ACCOUNT);
      if (legacy && (legacy.provider === provider || legacy.provider === undefined || legacy.provider === null)) {
        return { account: LEGACY_KEYCHAIN_ACCOUNT, token: { provider, ...legacy } };
      }
    }
    return null;
  }

  const tokens = await listStoredTokens();
  if (tokens.length === 0) return null;
  tokens.sort((a, b) => String(b.saved_at || '').localeCompare(String(a.saved_at || '')));
  const latest = tokens[0];
  return { account: latest.account, token: latest };
}

async function signedGet(path, sessionId, signSecretKeyB64) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const requestNonce = randomNonce();
  const canonical = `${timestamp}|${sessionId}|GET|${path}|${requestNonce}`;
  const signature = nacl.sign.detached(decodeUTF8(canonical), decodeBase64(signSecretKeyB64));

  return fetch(`${WORKER_URL}${path}`, {
    headers: {
      'x-timestamp': timestamp,
      'x-request-nonce': requestNonce,
      'x-signature': encodeBase64(signature)
    }
  });
}

function outputMaybeJson(payload, asJson) {
  if (asJson) {
    console.log(JSON.stringify(payload, null, 2));
  }
}

async function startFlow(provider, ttlSeconds, scope, asJson) {
  const signKeys = nacl.sign.keyPair();
  const boxKeys = nacl.box.keyPair();

  const initRes = await fetch(`${WORKER_URL}/init`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      provider,
      verifyKey: encodeBase64(signKeys.publicKey),
      boxPublicKey: encodeBase64(boxKeys.publicKey),
      scope: scope || undefined,
      ttlSeconds
    })
  });

  let parsed = null;
  try {
    parsed = await initRes.json();
  } catch {
    parsed = null;
  }

  if (!initRes.ok) {
    if (initRes.status === 501 && parsed?.featureRequestReceived) {
      throw new Error(`Provider not implemented yet: ${parsed.requestedProvider}. Feature request received by server.`);
    }
    throw new Error(`/init failed (${initRes.status}): ${parsed ? JSON.stringify(parsed) : 'invalid response'}`);
  }

  const { sessionId, shortAuthUrl, authUrl, expiresIn } = parsed;
  await saveSessionMaterial(sessionId, {
    provider,
    signSecretKey: encodeBase64(signKeys.secretKey),
    boxSecretKey: encodeBase64(boxKeys.secretKey),
    createdAt: new Date().toISOString(),
    expiresIn
  });

  if (asJson) {
    outputMaybeJson({
      action: 'start',
      provider,
      sessionId,
      expiresIn,
      shortAuthUrl: shortAuthUrl || null,
      authUrl: authUrl || null,
      statusCommand: `clawauth login status ${sessionId}`,
      claimCommand: `clawauth login claim ${sessionId}`
    }, true);
    return;
  }

  console.log(`Provider: ${provider}`);
  console.log(`Session: ${sessionId}`);
  console.log(`Expires in: ${expiresIn}s`);
  console.log(`Share this link with the user:\n${shortAuthUrl || authUrl}\n`);
  console.log('Session saved locally. Later run:');
  console.log(`  clawauth login status ${sessionId}`);
  console.log(`  clawauth login claim ${sessionId}`);
}

async function statusFlow(sessionId, asJson) {
  const session = await loadSessionMaterial(sessionId);
  if (!session) {
    throw new Error(`No local session material found for ${sessionId}`);
  }

  const res = await signedGet(`/status/${sessionId}`, sessionId, session.signSecretKey);
  let parsed;
  try {
    parsed = await res.json();
  } catch {
    throw new Error(`/status failed (${res.status}): invalid response`);
  }

  if (!res.ok && parsed.status !== 'error') {
    throw new Error(`/status failed (${res.status}): ${JSON.stringify(parsed)}`);
  }

  const payload = {
    action: 'status',
    sessionId,
    provider: parsed.provider || session.provider,
    status: parsed.status,
    error: parsed.error || null
  };

  if (asJson) {
    outputMaybeJson(payload, true);
    return;
  }

  if (parsed.status === 'error') {
    console.log(`Status: error (${payload.provider})`);
    console.log(`Reason: ${payload.error || 'unknown error'}`);
    return;
  }

  console.log(`Status: ${payload.status} (${payload.provider})`);
  if (parsed.status === 'completed') {
    console.log(`Ready to claim: clawauth login claim ${sessionId}`);
  }
}

async function claimFlow(sessionId, asJson) {
  const session = await loadSessionMaterial(sessionId);
  if (!session) {
    throw new Error(`No local session material found for ${sessionId}`);
  }

  const res = await signedGet(`/claim/${sessionId}`, sessionId, session.signSecretKey);
  let parsed;
  try {
    parsed = await res.json();
  } catch {
    throw new Error(`/claim failed (${res.status}): invalid response`);
  }

  if (!res.ok && parsed.status !== 'error') {
    throw new Error(`/claim failed (${res.status}): ${JSON.stringify(parsed)}`);
  }

  if (parsed.status === 'pending') {
    if (asJson) {
      outputMaybeJson({ action: 'claim', sessionId, status: 'pending', provider: parsed.provider || session.provider }, true);
      return;
    }
    console.log(`Status: pending (${parsed.provider || session.provider})`);
    return;
  }

  if (parsed.status === 'error') {
    await deleteSessionMaterial(sessionId);
    throw new Error(`OAuth callback failed: ${parsed.error || 'unknown error'}`);
  }

  const decrypted = decryptBlob(parsed.blob, session.boxSecretKey);
  const tokenProvider = decrypted?.provider || session.provider;
  const stored = await saveRefreshToken(tokenProvider, decrypted?.tokenData);
  await deleteSessionMaterial(sessionId);

  if (asJson) {
    outputMaybeJson({
      action: 'claim',
      sessionId,
      status: 'completed',
      provider: tokenProvider,
      tokenData: decrypted?.tokenData || null,
      storedInKeychain: stored,
      keychainService: KEYCHAIN_SERVICE,
      keychainAccount: keychainAccountForProvider(tokenProvider)
    }, true);
    return;
  }

  console.log('Token received (decrypted):');
  console.log(JSON.stringify(decrypted, null, 2));
  if (stored) {
    console.log(`Refresh token stored in keychain (${KEYCHAIN_SERVICE}/${keychainAccountForProvider(tokenProvider)}).`);
  } else {
    console.log('No refresh token in response; keychain not updated.');
  }
  console.log('Session material deleted from local keychain.');
}

async function waitFlow(sessionId, timeoutMs, intervalMs, asJson) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const session = await loadSessionMaterial(sessionId);
    if (!session) {
      throw new Error(`No local session material found for ${sessionId}`);
    }

    const res = await signedGet(`/status/${sessionId}`, sessionId, session.signSecretKey);
    const status = await res.json();

    if (status.status === 'completed') {
      await claimFlow(sessionId, asJson);
      return;
    }

    if (status.status === 'error') {
      await deleteSessionMaterial(sessionId);
      throw new Error(`OAuth callback failed: ${status.error || 'unknown error'}`);
    }

    if (!asJson) {
      console.log(`Waiting for user (${status.provider || session.provider})...`);
    }
    await sleep(intervalMs);
  }

  throw new Error('Polling timeout reached');
}

async function sessionsFlow(asJson) {
  const sessions = await listSessionMaterials();
  if (sessions.length === 0) {
    if (asJson) {
      outputMaybeJson({ action: 'sessions', sessions: [] }, true);
      return;
    }
    console.log('No local sessions found.');
    return;
  }

  sessions.sort((a, b) => {
    const pa = String(a.provider || '');
    const pb = String(b.provider || '');
    if (pa !== pb) return pa.localeCompare(pb);
    return String(a.sessionId).localeCompare(String(b.sessionId));
  });

  const rows = [];
  for (const session of sessions) {
    const row = {
      sessionId: session.sessionId,
      provider: session.provider || 'unknown',
      createdAt: session.createdAt || null,
      ttl: session.expiresIn || null,
      status: 'unknown',
      error: null
    };

    if (session.parseError || !session.signSecretKey) {
      row.status = 'local_corrupt';
      rows.push(row);
      continue;
    }

    try {
      const res = await signedGet(`/status/${session.sessionId}`, session.sessionId, session.signSecretKey);
      const body = await res.json();
      row.status = body.status || `http_${res.status}`;
      row.error = body.error || null;
    } catch {
      row.status = 'status_check_failed';
    }

    rows.push(row);
  }

  if (asJson) {
    outputMaybeJson({ action: 'sessions', sessions: rows }, true);
    return;
  }

  console.log(`Local sessions: ${rows.length}`);
  let currentProvider = '';
  for (const row of rows) {
    if (row.provider !== currentProvider) {
      currentProvider = row.provider;
      console.log(`\n[${currentProvider}]`);
    }
    const err = row.error ? `:${row.error}` : '';
    const created = row.createdAt || 'unknown_created_at';
    const ttl = row.ttl || 'unknown_ttl';
    console.log(`- ${row.sessionId}  status=${row.status}${err}  createdAt=${created}  ttl=${ttl}s`);
  }
}

async function sessionRemoveFlow(sessionId, asJson) {
  const existed = Boolean(await loadSessionMaterial(sessionId));
  await deleteSessionMaterial(sessionId);
  if (asJson) {
    outputMaybeJson({ action: 'sessions.rm', sessionId, removed: existed }, true);
    return;
  }
  if (existed) {
    console.log(`Removed local session material for ${sessionId}.`);
  } else {
    console.log(`No local session material found for ${sessionId}.`);
  }
}

async function providersFlow(asJson) {
  const res = await fetch(`${WORKER_URL}/providers`);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`/providers failed (${res.status}): ${body}`);
  }
  const data = await res.json();
  const providers = Array.isArray(data.providers) ? data.providers : [];
  if (asJson) {
    outputMaybeJson({ action: 'providers.list', providers }, true);
    return;
  }
  if (providers.length === 0) {
    console.log('No providers reported by server.');
    return;
  }
  console.log('Supported providers:');
  for (const p of providers) {
    console.log(`- ${p}`);
  }
}

function printTokenEnv(record) {
  const provider = String(record.token.provider || 'unknown').toUpperCase().replace(/[^A-Z0-9]/g, '_');
  const access = record.token.access_token || '';
  const refresh = record.token.refresh_token || '';
  const tokenType = record.token.token_type || '';
  console.log(`# account=${record.account}`);
  console.log(`export CLAWAUTH_PROVIDER="${record.token.provider || 'unknown'}"`);
  console.log(`export CLAWAUTH_ACCESS_TOKEN="${access}"`);
  console.log(`export CLAWAUTH_REFRESH_TOKEN="${refresh}"`);
  console.log(`export CLAWAUTH_TOKEN_TYPE="${tokenType}"`);
  console.log(`export ${provider}_ACCESS_TOKEN="${access}"`);
  console.log(`export ${provider}_REFRESH_TOKEN="${refresh}"`);
}

async function tokenFlow(action, provider, asJson) {
  const normalized = (action || 'get').toLowerCase();

  if (normalized === 'list') {
    const tokens = await listStoredTokens();
    if (asJson) {
      outputMaybeJson({ action: 'token.list', tokens }, true);
      return;
    }
    if (tokens.length === 0) {
      console.log('No stored tokens found.');
      return;
    }

    tokens.sort((a, b) => String(a.provider || '').localeCompare(String(b.provider || '')));
    console.log(`Stored tokens: ${tokens.length}`);
    for (const token of tokens) {
      console.log(`- provider=${token.provider || 'unknown'} account=${token.account} saved_at=${token.saved_at || 'unknown'}`);
    }
    return;
  }

  if (normalized !== 'get' && normalized !== 'env') {
    throw new Error('Unknown token action. Use: token list|get|env');
  }

  const record = await resolveTokenRecord(provider || '');
  if (!record) {
    throw new Error(provider ? `No stored token found for provider '${provider}'` : 'No stored token found');
  }

  if (normalized === 'env') {
    if (asJson) {
      outputMaybeJson({ action: 'token.env', account: record.account, provider: record.token.provider, token: record.token }, true);
      return;
    }
    printTokenEnv(record);
    return;
  }

  outputMaybeJson({ action: 'token.get', account: record.account, token: record.token }, asJson);
  if (!asJson) {
    console.log(JSON.stringify({
      provider: record.token.provider || 'unknown',
      account: record.account,
      token_type: record.token.token_type || null,
      access_token: record.token.access_token || null,
      refresh_token: record.token.refresh_token || null,
      saved_at: record.token.saved_at || null
    }, null, 2));
  }
}

async function fetchProviderNames() {
  const res = await fetch(`${WORKER_URL}/providers`);
  if (!res.ok) {
    return [];
  }
  try {
    const data = await res.json();
    return Array.isArray(data.providers) ? data.providers : [];
  } catch {
    return [];
  }
}

function formatProviderHint(providers) {
  if (!providers || providers.length === 0) {
    return 'Run: clawauth providers';
  }
  return `Supported providers: ${providers.join(', ')}`;
}

async function run() {
  const program = new Command();
  program
    .name('clawauth')
    .description('Agent-first async OAuth CLI with short links, session claiming, and keychain token storage.')
    .showHelpAfterError()
    .addHelpText('after', [
      '',
      'Quick start:',
      '  clawauth login start notion',
      '  clawauth login status <sessionId>',
      '  clawauth login claim <sessionId>',
      '',
      'Session inventory:',
      '  clawauth sessions',
      '',
      'Token retrieval:',
      '  clawauth token list',
      '  clawauth token get notion',
      '  clawauth token env notion',
      '',
      'Provider discovery:',
      '  clawauth providers',
      '',
      'Detailed docs:',
      '  clawauth explain',
      '  clawauth docs',
      '  clawauth login --help'
    ].join('\n'));

  const login = program.command('login').description('OAuth login flow commands (start/status/claim/wait).');

  login
    .command('start [provider]')
    .description('Start auth flow and exit immediately. Saves session material locally for later status/claim.')
    .option('--ttl <seconds>', 'Session TTL in seconds (default: 3600)', String(DEFAULT_TTL_SECONDS))
    .option('--scope <scope>', 'OAuth scope override (provider-specific format)', DEFAULT_SCOPE)
    .option('--json', 'Output JSON')
    .addHelpText('after', '\nTip:\n  Run `clawauth providers` to list all supported providers.')
    .action(async (provider, options) => {
      const normalizedProvider = String(provider || '').toLowerCase().trim();
      if (!normalizedProvider) {
        const providers = await fetchProviderNames();
        throw new Error(`Missing provider. ${formatProviderHint(providers)}`);
      }
      const ttl = Number(options.ttl);
      if (!Number.isFinite(ttl) || ttl <= 0) {
        throw new Error('Invalid --ttl value');
      }
      await startFlow(normalizedProvider, Math.floor(ttl), options.scope || '', Boolean(options.json));
    });

  login
    .command('status <sessionId>')
    .description('Check remote status of a previously started session.')
    .option('--json', 'Output JSON')
    .action(async (sessionId, options) => {
      await statusFlow(sessionId, Boolean(options.json));
    });

  login
    .command('claim <sessionId>')
    .description('Claim completed session, decrypt token blob, store refresh token in keychain.')
    .option('--json', 'Output JSON')
    .action(async (sessionId, options) => {
      await claimFlow(sessionId, Boolean(options.json));
    });

  login
    .command('wait <sessionId>')
    .description('Blocking convenience mode: poll status until completed, then claim.')
    .option('--timeout <ms>', 'Wait timeout in milliseconds', String(POLL_TIMEOUT_MS))
    .option('--interval <ms>', 'Polling interval in milliseconds', String(POLL_INTERVAL_MS))
    .option('--json', 'Output JSON')
    .action(async (sessionId, options) => {
      const timeout = Number(options.timeout);
      const interval = Number(options.interval);
      if (!Number.isFinite(timeout) || timeout <= 0) throw new Error('Invalid --timeout value');
      if (!Number.isFinite(interval) || interval <= 0) throw new Error('Invalid --interval value');
      await waitFlow(sessionId, Math.floor(timeout), Math.floor(interval), Boolean(options.json));
    });

  login
    .addHelpText('after', [
      '',
      'Flow:',
      '  1) clawauth login start <provider> [--ttl 3600]',
      '  2) Send shortAuthUrl to user',
      '  3) clawauth login status <sessionId>',
      '  4) clawauth login claim <sessionId>'
    ].join('\n'));

  program
    .command('sessions')
    .description('List local sessions grouped by provider with live status checks.')
    .option('--json', 'Output JSON')
    .action(async (options) => {
      await sessionsFlow(Boolean(options.json));
    });

  program
    .command('session-rm <sessionId>')
    .description('Delete local session material for a sessionId.')
    .option('--json', 'Output JSON')
    .action(async (sessionId, options) => {
      await sessionRemoveFlow(sessionId, Boolean(options.json));
    });

  program
    .command('token [action] [provider]')
    .description('Token retrieval from keychain. Actions: list, get, env.')
    .option('--json', 'Output JSON (for get/list/env)')
    .addHelpText('after', '\nExamples:\n  clawauth token list\n  clawauth token get notion\n  clawauth token env notion\n  eval "$(clawauth token env notion)"')
    .action(async (action, provider, options) => {
      await tokenFlow(action || 'get', provider ? String(provider).toLowerCase() : '', Boolean(options.json));
    });

  program
    .command('providers')
    .description('List providers supported by the server.')
    .option('--json', 'Output JSON')
    .action(async (options) => {
      await providersFlow(Boolean(options.json));
    });

  program
    .command('explain')
    .alias('docs')
    .description('Print detailed manual-style usage documentation.')
    .action(() => {
      console.log(MANUAL_TEXT.trim());
    });

  await program.parseAsync(process.argv);
}

run().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
