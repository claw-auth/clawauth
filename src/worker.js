import nacl from 'tweetnacl';
import util from 'tweetnacl-util';

const { decodeBase64, decodeUTF8, encodeBase64, encodeUTF8 } = util;

const DEFAULT_SESSION_TTL_SECONDS = 3600;
const MIN_SESSION_TTL_SECONDS = 60;
const MAX_SESSION_TTL_SECONDS = 86400;
const MAX_TIMESTAMP_SKEW_SECONDS = 60;
const MAX_POLL_COUNT = 2400;
const MIN_POLL_INTERVAL_MS = 250;
const NONCE_CACHE_SIZE = 96;

const PROVIDERS = {
  notion: {
    authUrl: 'https://api.notion.com/v1/oauth/authorize',
    tokenUrl: 'https://api.notion.com/v1/oauth/token',
    authMethod: 'basic',
    authorizeParams: { owner: 'user' }
  },
  github: {
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    authMethod: 'post',
    tokenHeaders: { accept: 'application/json' }
  },
  discord: {
    authUrl: 'https://discord.com/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    authMethod: 'post'
  },
  linear: {
    authUrl: 'https://linear.app/oauth/authorize',
    tokenUrl: 'https://api.linear.app/oauth/token',
    authMethod: 'post'
  },
  airtable: {
    authUrl: 'https://airtable.com/oauth2/v1/authorize',
    tokenUrl: 'https://airtable.com/oauth2/v1/token',
    authMethod: 'post'
  },
  todoist: {
    authUrl: 'https://todoist.com/oauth/authorize',
    tokenUrl: 'https://todoist.com/oauth/access_token',
    authMethod: 'post'
  },
  asana: {
    authUrl: 'https://app.asana.com/-/oauth_authorize',
    tokenUrl: 'https://app.asana.com/-/oauth_token',
    authMethod: 'post'
  },
  trello: {
    authUrl: 'https://auth.atlassian.com/authorize',
    tokenUrl: 'https://auth.atlassian.com/oauth/token',
    authMethod: 'post',
    authorizeParams: { audience: 'api.atlassian.com' }
  },
  dropbox: {
    authUrl: 'https://www.dropbox.com/oauth2/authorize',
    tokenUrl: 'https://api.dropboxapi.com/oauth2/token',
    authMethod: 'post'
  },
  digitalocean: {
    authUrl: 'https://cloud.digitalocean.com/v1/oauth/authorize',
    tokenUrl: 'https://cloud.digitalocean.com/v1/oauth/token',
    authMethod: 'post'
  },
  slack: {
    authUrl: 'https://slack.com/oauth/v2/authorize',
    tokenUrl: 'https://slack.com/api/oauth.v2.access',
    authMethod: 'post'
  },
  gitlab: {
    authUrl: 'https://gitlab.com/oauth/authorize',
    tokenUrl: 'https://gitlab.com/oauth/token',
    authMethod: 'post'
  },
  reddit: {
    authUrl: 'https://www.reddit.com/api/v1/authorize',
    tokenUrl: 'https://www.reddit.com/api/v1/access_token',
    authMethod: 'basic'
  },
  figma: {
    authUrl: 'https://www.figma.com/oauth',
    tokenUrl: 'https://www.figma.com/api/oauth/token',
    authMethod: 'post'
  },
  spotify: {
    authUrl: 'https://accounts.spotify.com/authorize',
    tokenUrl: 'https://accounts.spotify.com/api/token',
    authMethod: 'basic'
  },
  bitbucket: {
    authUrl: 'https://bitbucket.org/site/oauth2/authorize',
    tokenUrl: 'https://bitbucket.org/site/oauth2/access_token',
    authMethod: 'basic'
  },
  box: {
    authUrl: 'https://account.box.com/api/oauth2/authorize',
    tokenUrl: 'https://api.box.com/oauth2/token',
    authMethod: 'post'
  },
  calendly: {
    authUrl: 'https://auth.calendly.com/oauth/authorize',
    tokenUrl: 'https://auth.calendly.com/oauth/token',
    authMethod: 'post'
  },
  fathom: {
    authUrl: 'https://fathom.video/oauth/authorize',
    tokenUrl: 'https://api.fathom.video/oauth/token',
    authMethod: 'post'
  },
  twitch: {
    authUrl: 'https://id.twitch.tv/oauth2/authorize',
    tokenUrl: 'https://id.twitch.tv/oauth2/token',
    authMethod: 'post'
  }
};

const PROVIDER_NAMES = Object.keys(PROVIDERS);

function safeString(value, maxLength = 120) {
  return String(value ?? '').slice(0, maxLength);
}

function trackEvent(env, request, event, details = {}) {
  const analytics = env.ANALYTICS;
  if (!analytics || typeof analytics.writeDataPoint !== 'function') {
    return;
  }

  let pathname = '';
  try {
    pathname = new URL(request.url).pathname;
  } catch {
    pathname = '';
  }

  try {
    analytics.writeDataPoint({
      indexes: [
        safeString(event, 64),
        safeString(details.provider || details.requestedProvider || 'unknown', 80),
        safeString(details.result || 'unknown', 40)
      ],
      doubles: [
        Date.now(),
        Number(details.httpStatus || 0),
        Number(details.expiresIn || 0)
      ],
      blobs: [
        safeString(details.requestedProvider || '', 120),
        safeString(details.errorCode || '', 120),
        safeString(request.method, 12),
        safeString(pathname, 200),
        safeString(request?.cf?.country || '', 8),
        safeString(request?.cf?.colo || '', 16),
        safeString(request.headers.get('user-agent') || '', 240)
      ]
    });
  } catch (error) {
    console.warn(`analytics write failed: ${error?.message || 'unknown_error'}`);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store'
    }
  });
}

function badRequest(message) {
  return json({ error: message }, 400);
}

function notImplemented(data) {
  return json(data, 501);
}

function unauthorized(message = 'Unauthorized') {
  return json({ error: message }, 401);
}

function notFound(message = 'Not found') {
  return json({ error: message }, 404);
}

function tooManyRequests(message = 'Too many requests') {
  return json({ error: message }, 429);
}

function messagePage(title, body, status = 200) {
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <style>
      :root { color-scheme: light; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: #f8fafc;
        color: #0f172a;
        font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      main {
        width: min(560px, 92vw);
        text-align: center;
      }
      h1 {
        margin: 0 0 12px;
        font-size: 28px;
        font-weight: 800;
        letter-spacing: -0.02em;
      }
      p {
        margin: 0;
        font-size: 16px;
        line-height: 1.5;
        color: #334155;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>${title}</h1>
      <p>${body}</p>
    </main>
  </body>
</html>`;
  return new Response(html, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }
  });
}

function clampTtl(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return null;
  }
  return Math.max(MIN_SESSION_TTL_SECONDS, Math.min(MAX_SESSION_TTL_SECONDS, Math.floor(n)));
}

function resolveSessionTtl(requestTtl, env) {
  const envTtl = clampTtl(env.SESSION_TTL_SECONDS);
  const base = envTtl || DEFAULT_SESSION_TTL_SECONDS;
  const req = clampTtl(requestTtl);
  return req || base;
}

function sessionTtl(session, env) {
  return clampTtl(session?.sessionTtl) || resolveSessionTtl(null, env);
}

function tryDecodeBase64(value) {
  try {
    return decodeBase64(value);
  } catch {
    return null;
  }
}

function toBase64Url(bytes) {
  return encodeBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (b64.length % 4)) % 4;
  return decodeBase64(`${b64}${'='.repeat(padLen)}`);
}

function safeEqual(a, b) {
  const aBytes = decodeUTF8(a);
  const bBytes = decodeUTF8(b);
  if (aBytes.length !== bBytes.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < aBytes.length; i += 1) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}

function providerPrefix(provider) {
  return provider.toUpperCase().replace(/[^A-Z0-9]/g, '_');
}

function pickProvider(providerInput) {
  const provider = String(providerInput || '').trim().toLowerCase();
  if (!/^[a-z0-9_-]+$/.test(provider)) {
    return null;
  }
  return provider;
}

function loadProviderConfig(provider, env, origin) {
  const base = PROVIDERS[provider];
  if (!base) {
    return null;
  }

  const prefix = providerPrefix(provider);
  const clientId = env[`${prefix}_CLIENT_ID`];
  const clientSecret = env[`${prefix}_CLIENT_SECRET`];
  const redirectUri = env[`${prefix}_REDIRECT_URI`] || `${origin}/callback`;
  const authUrl = env[`${prefix}_AUTH_URL`] || base.authUrl;
  const tokenUrl = env[`${prefix}_TOKEN_URL`] || base.tokenUrl;

  return {
    ...base,
    provider,
    prefix,
    clientId,
    clientSecret,
    redirectUri,
    authUrl,
    tokenUrl
  };
}

function ensureProviderSecrets(config) {
  if (!config.clientId || !config.clientSecret) {
    return `Worker misconfigured for provider '${config.provider}': missing ${config.prefix}_CLIENT_ID/${config.prefix}_CLIENT_SECRET`;
  }
  return null;
}

function buildAuthorizeUrl(config, authState, scope) {
  const url = new URL(config.authUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.redirectUri);
  url.searchParams.set('state', authState);

  const authorizeParams = config.authorizeParams || {};
  for (const [key, value] of Object.entries(authorizeParams)) {
    if (!url.searchParams.has(key)) {
      url.searchParams.set(key, String(value));
    }
  }

  if (scope) {
    url.searchParams.set('scope', scope);
  }

  return url.toString();
}

function parseTokenResponse(text, contentType) {
  if ((contentType || '').includes('application/json')) {
    return JSON.parse(text);
  }

  const asQuery = new URLSearchParams(text);
  const queryObj = Object.fromEntries(asQuery.entries());
  if (Object.keys(queryObj).length > 0) {
    return queryObj;
  }

  throw new Error('Unable to parse token response');
}

async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    decodeUTF8(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, decodeUTF8(message));
  return toBase64Url(new Uint8Array(sig));
}

async function createSignedState(sessionId, provider, secret, ttlSeconds) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const nonce = toBase64Url(nacl.randomBytes(16));
  const payload = `${sessionId}.${provider}.${nonce}.${exp}`;
  const sig = await hmacSign(secret, payload);
  return `${payload}.${sig}`;
}

async function parseAndVerifyState(state, secret) {
  if (!state) {
    return null;
  }

  const parts = state.split('.');
  if (parts.length !== 5) {
    return null;
  }

  const [sessionId, provider, nonce, expRaw, signature] = parts;
  if (!sessionId || !provider || !nonce || !/^\d+$/.test(expRaw) || !signature) {
    return null;
  }

  if (!PROVIDERS[provider]) {
    return null;
  }

  try {
    fromBase64Url(nonce);
  } catch {
    return null;
  }

  const exp = Number(expRaw);
  const now = Math.floor(Date.now() / 1000);
  if (exp < now) {
    return null;
  }

  const payload = `${sessionId}.${provider}.${nonce}.${expRaw}`;
  const expected = await hmacSign(secret, payload);
  if (!safeEqual(signature, expected)) {
    return null;
  }

  return { sessionId, provider };
}

function encryptForClient(boxPublicKeyB64, payload) {
  const recipientPub = tryDecodeBase64(boxPublicKeyB64);
  if (!recipientPub || recipientPub.length !== nacl.box.publicKeyLength) {
    throw new Error('Invalid boxPublicKey');
  }

  const eph = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const plaintext = decodeUTF8(JSON.stringify(payload));
  const ciphertext = nacl.box(plaintext, nonce, recipientPub, eph.secretKey);

  return {
    ephemeralPublicKey: encodeBase64(eph.publicKey),
    nonce: encodeBase64(nonce),
    ciphertext: encodeBase64(ciphertext)
  };
}

async function exchangeCodeForToken(config, code) {
  const misconfig = ensureProviderSecrets(config);
  if (misconfig) {
    throw new Error(misconfig);
  }

  const params = new URLSearchParams();
  params.set('grant_type', 'authorization_code');
  params.set('code', code);
  params.set('redirect_uri', config.redirectUri);

  const headers = {
    'content-type': 'application/x-www-form-urlencoded'
  };

  if (config.authMethod === 'basic') {
    const auth = btoa(`${config.clientId}:${config.clientSecret}`);
    headers.authorization = `Basic ${auth}`;
  } else {
    params.set('client_id', config.clientId);
    params.set('client_secret', config.clientSecret);
  }

  if (config.tokenHeaders) {
    for (const [key, value] of Object.entries(config.tokenHeaders)) {
      headers[key] = value;
    }
  }

  const res = await fetch(config.tokenUrl, {
    method: 'POST',
    headers,
    body: params.toString()
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${config.provider} token exchange failed (${res.status}): ${text.slice(0, 600)}`);
  }

  return parseTokenResponse(text, res.headers.get('content-type'));
}

function validateFreshTimestamp(timestamp) {
  if (!timestamp || !/^\d+$/.test(timestamp)) {
    return false;
  }

  const ts = Number(timestamp);
  const now = Math.floor(Date.now() / 1000);
  return Math.abs(now - ts) <= MAX_TIMESTAMP_SKEW_SECONDS;
}

function validateNonce(nonce) {
  return typeof nonce === 'string' && nonce.length >= 12 && nonce.length <= 120 && /^[A-Za-z0-9_-]+$/.test(nonce);
}

function verifySignedRequest(session, sessionId, request, pathname) {
  const signatureB64 = request.headers.get('x-signature') || '';
  const timestamp = request.headers.get('x-timestamp') || '';
  const requestNonce = request.headers.get('x-request-nonce') || '';

  if (!validateFreshTimestamp(timestamp)) {
    return { ok: false, code: 'invalid_timestamp', response: unauthorized('Invalid or stale timestamp') };
  }
  if (!validateNonce(requestNonce)) {
    return { ok: false, code: 'invalid_nonce', response: unauthorized('Invalid request nonce') };
  }

  const nowMs = Date.now();
  if (session.lastPollAt && nowMs - session.lastPollAt < MIN_POLL_INTERVAL_MS) {
    return { ok: false, code: 'polling_too_fast', response: tooManyRequests('Polling too fast') };
  }
  if ((session.pollCount || 0) >= MAX_POLL_COUNT) {
    return { ok: false, code: 'polling_limit_reached', response: tooManyRequests('Polling limit reached') };
  }
  if ((session.usedNonces || []).includes(requestNonce)) {
    return { ok: false, code: 'replay_detected', response: unauthorized('Replay detected') };
  }

  const sigBytes = tryDecodeBase64(signatureB64);
  const verifyBytes = tryDecodeBase64(session.verifyKey || '');
  if (!sigBytes || sigBytes.length !== nacl.sign.signatureLength || !verifyBytes) {
    return { ok: false, code: 'invalid_signature_format', response: unauthorized() };
  }

  const canonical = `${timestamp}|${sessionId}|GET|${pathname}|${requestNonce}`;
  const valid = nacl.sign.detached.verify(
    decodeUTF8(canonical),
    sigBytes,
    verifyBytes
  );
  if (!valid) {
    return { ok: false, code: 'signature_verification_failed', response: unauthorized() };
  }

  const usedNonces = [...(session.usedNonces || []), requestNonce].slice(-NONCE_CACHE_SIZE);
  const nextSession = {
    ...session,
    pollCount: (session.pollCount || 0) + 1,
    lastPollAt: nowMs,
    usedNonces
  };

  return { ok: true, nextSession };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const defaultOrigin = `${url.protocol}//${url.host}`;
    const origin = env.PUBLIC_BASE_URL || defaultOrigin;

    if (!env.STATE_SIGNING_SECRET) {
      trackEvent(env, request, 'worker_config_error', {
        result: 'error',
        httpStatus: 500,
        errorCode: 'missing_state_signing_secret'
      });
      return json({ error: 'Worker misconfigured: missing STATE_SIGNING_SECRET' }, 500);
    }

    if (url.pathname === '/providers' && request.method === 'GET') {
      trackEvent(env, request, 'providers_list', {
        result: 'ok',
        httpStatus: 200
      });
      return json({ providers: PROVIDER_NAMES });
    }

    const pathParts = url.pathname.split('/').filter(Boolean);
    if (request.method === 'GET' && pathParts.length === 2 && PROVIDERS[pathParts[0]]) {
      const provider = pathParts[0];
      const sessionId = pathParts[1];
      const raw = await env.KV.get(sessionId);
      if (!raw) {
        trackEvent(env, request, 'shortlink_redirect', {
          provider,
          result: 'error',
          httpStatus: 404,
          errorCode: 'session_not_found'
        });
        return messagePage('Session Expired', 'This authentication session was not found or has expired.', 404);
      }

      const session = JSON.parse(raw);
      if (session.provider !== provider) {
        trackEvent(env, request, 'shortlink_redirect', {
          provider,
          result: 'error',
          httpStatus: 400,
          errorCode: 'provider_session_mismatch'
        });
        return messagePage('Session Error', 'Provider and session do not match.', 400);
      }

      if (session.status === 'completed') {
        trackEvent(env, request, 'shortlink_redirect', {
          provider,
          result: 'already_completed',
          httpStatus: 410
        });
        return messagePage('Already Completed', 'This authentication session is already complete.', 410);
      }

      if (session.status === 'error') {
        trackEvent(env, request, 'shortlink_redirect', {
          provider,
          result: 'error',
          httpStatus: 400,
          errorCode: safeString(session.error || 'session_error', 120)
        });
        return messagePage('Session Error', `Session failed: ${session.error || 'unknown error'}`, 400);
      }

      if (!session.authUrl) {
        trackEvent(env, request, 'shortlink_redirect', {
          provider,
          result: 'error',
          httpStatus: 500,
          errorCode: 'missing_auth_url'
        });
        return messagePage('Server Error', 'Missing auth URL for this session.', 500);
      }

      trackEvent(env, request, 'shortlink_redirect', {
        provider,
        result: 'ok',
        httpStatus: 302
      });
      return Response.redirect(session.authUrl, 302);
    }

    if (url.pathname === '/init' && request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch {
        trackEvent(env, request, 'init_session', {
          result: 'error',
          httpStatus: 400,
          errorCode: 'invalid_json'
        });
        return badRequest('Invalid JSON');
      }

      const { verifyKey, boxPublicKey, provider: providerInput, scope, ttlSeconds } = body ?? {};
      const provider = pickProvider(providerInput);
      if (!provider) {
        trackEvent(env, request, 'init_session', {
          requestedProvider: safeString(providerInput, 80),
          result: 'error',
          httpStatus: 400,
          errorCode: 'invalid_provider'
        });
        return badRequest('Missing or invalid provider. Pass provider explicitly.');
      }
      if (!PROVIDERS[provider]) {
        trackEvent(env, request, 'init_session', {
          requestedProvider: provider,
          result: 'not_implemented',
          httpStatus: 501,
          errorCode: 'provider_not_implemented'
        });
        return notImplemented({
          status: 'not_implemented',
          featureRequestReceived: true,
          requestedProvider: provider,
          message: `Provider '${provider}' is not implemented yet.`,
          supportedProviders: PROVIDER_NAMES
        });
      }

      const config = loadProviderConfig(provider, env, origin);
      const misconfig = ensureProviderSecrets(config);
      if (misconfig) {
        trackEvent(env, request, 'init_session', {
          provider,
          requestedProvider: providerInput,
          result: 'error',
          httpStatus: 500,
          errorCode: 'provider_misconfigured'
        });
        return json({ error: misconfig }, 500);
      }

      const verifyBytes = tryDecodeBase64(verifyKey || '');
      const boxBytes = tryDecodeBase64(boxPublicKey || '');

      if (!verifyBytes || verifyBytes.length !== nacl.sign.publicKeyLength) {
        trackEvent(env, request, 'init_session', {
          provider,
          result: 'error',
          httpStatus: 400,
          errorCode: 'invalid_verify_key'
        });
        return badRequest('verifyKey must be base64 Ed25519 public key');
      }
      if (!boxBytes || boxBytes.length !== nacl.box.publicKeyLength) {
        trackEvent(env, request, 'init_session', {
          provider,
          result: 'error',
          httpStatus: 400,
          errorCode: 'invalid_box_public_key'
        });
        return badRequest('boxPublicKey must be base64 Curve25519 public key');
      }

      const sessionTtlSeconds = resolveSessionTtl(ttlSeconds, env);
      const sessionId = crypto.randomUUID();
      const authState = await createSignedState(sessionId, provider, env.STATE_SIGNING_SECRET, sessionTtlSeconds);
      const authUrl = buildAuthorizeUrl(config, authState, scope);

      await env.KV.put(
        sessionId,
        JSON.stringify({
          provider,
          authUrl,
          verifyKey,
          boxPublicKey,
          status: 'pending',
          createdAt: new Date().toISOString(),
          pollCount: 0,
          lastPollAt: 0,
          usedNonces: [],
          sessionTtl: sessionTtlSeconds
        }),
        { expirationTtl: sessionTtlSeconds }
      );

      const shortAuthUrl = `${origin}/${provider}/${sessionId}`;
      trackEvent(env, request, 'init_session', {
        provider,
        requestedProvider: providerInput,
        result: 'ok',
        httpStatus: 200,
        expiresIn: sessionTtlSeconds
      });
      return json({
        sessionId,
        provider,
        authState,
        authUrl,
        shortAuthUrl,
        expiresIn: sessionTtlSeconds
      });
    }

    if (url.pathname === '/callback' && request.method === 'GET') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const oauthError = url.searchParams.get('error');
      const oauthErrorDescription = url.searchParams.get('error_description');

      if (!state) {
        trackEvent(env, request, 'oauth_callback', {
          result: 'error',
          httpStatus: 400,
          errorCode: 'missing_state'
        });
        return badRequest('Missing state');
      }

      const stateData = await parseAndVerifyState(state, env.STATE_SIGNING_SECRET);
      if (!stateData) {
        trackEvent(env, request, 'oauth_callback', {
          result: 'error',
          httpStatus: 401,
          errorCode: 'invalid_state'
        });
        return unauthorized('Invalid state');
      }

      const { sessionId, provider } = stateData;
      const raw = await env.KV.get(sessionId);
      if (!raw) {
        trackEvent(env, request, 'oauth_callback', {
          provider,
          result: 'error',
          httpStatus: 404,
          errorCode: 'session_not_found'
        });
        return notFound('Session not found or expired');
      }

      const session = JSON.parse(raw);
      if (session.provider !== provider) {
        trackEvent(env, request, 'oauth_callback', {
          provider,
          result: 'error',
          httpStatus: 401,
          errorCode: 'state_provider_mismatch'
        });
        return unauthorized('State/provider mismatch');
      }

      if (oauthError) {
        await env.KV.put(
          sessionId,
          JSON.stringify({
            ...session,
            status: 'error',
            error: `${provider} authorize failed: ${oauthError}${oauthErrorDescription ? ` (${oauthErrorDescription})` : ''}`,
            failedAt: new Date().toISOString()
          }),
          { expirationTtl: sessionTtl(session, env) }
        );
        trackEvent(env, request, 'oauth_callback', {
          provider,
          result: 'error',
          httpStatus: 400,
          errorCode: safeString(`oauth_error:${oauthError}`, 120)
        });
        return messagePage('Authentication Failed', `${provider} returned: ${oauthError}.`, 400);
      }

      if (!code) {
        trackEvent(env, request, 'oauth_callback', {
          provider,
          result: 'error',
          httpStatus: 400,
          errorCode: 'missing_code'
        });
        return badRequest('Missing code');
      }

      if (session.status === 'completed') {
        trackEvent(env, request, 'oauth_callback', {
          provider,
          result: 'already_completed',
          httpStatus: 200
        });
        return messagePage('Already Completed', 'This authentication session has already been completed.', 200);
      }

      try {
        const config = loadProviderConfig(provider, env, origin);
        const tokenData = await exchangeCodeForToken(config, code);
        const blob = encryptForClient(session.boxPublicKey, {
          provider,
          issuedAt: new Date().toISOString(),
          tokenData
        });

        await env.KV.put(
          sessionId,
          JSON.stringify({
            ...session,
            status: 'completed',
            blob,
            completedAt: new Date().toISOString()
          }),
          { expirationTtl: sessionTtl(session, env) }
        );

        trackEvent(env, request, 'oauth_callback', {
          provider,
          result: 'ok',
          httpStatus: 200
        });
        return messagePage(
          'Authentication Complete',
          `Your ${provider} account is connected. You can close this tab now.`,
          200
        );
      } catch (error) {
        await env.KV.put(
          sessionId,
          JSON.stringify({
            ...session,
            status: 'error',
            error: String(error?.message || 'unknown callback error'),
            failedAt: new Date().toISOString()
          }),
          { expirationTtl: sessionTtl(session, env) }
        );

        trackEvent(env, request, 'oauth_callback', {
          provider,
          result: 'error',
          httpStatus: 500,
          errorCode: safeString(error?.message || 'callback_error', 120)
        });
        return messagePage('Authentication Error', `Callback failed: ${error.message}`, 500);
      }
    }

    if (url.pathname.startsWith('/status/') && request.method === 'GET') {
      const sessionId = url.pathname.split('/').pop();
      if (!sessionId) {
        return badRequest('Missing sessionId');
      }

      const raw = await env.KV.get(sessionId);
      if (!raw) {
        return notFound('Session not found or expired');
      }

      const session = JSON.parse(raw);
      const checked = verifySignedRequest(session, sessionId, request, `/status/${sessionId}`);
      if (!checked.ok) {
        trackEvent(env, request, 'status_poll', {
          provider: session.provider,
          result: 'error',
          httpStatus: checked.response.status,
          errorCode: checked.code || 'verification_failed'
        });
        return checked.response;
      }

      const nextSession = checked.nextSession;
      if (session.status === 'error') {
        await env.KV.put(sessionId, JSON.stringify(nextSession), { expirationTtl: sessionTtl(session, env) });
        trackEvent(env, request, 'status_poll', {
          provider: session.provider,
          result: 'session_error',
          httpStatus: 400,
          errorCode: safeString(session.error || 'callback_failed', 120)
        });
        return json({ status: 'error', provider: session.provider, error: session.error || 'callback_failed' }, 400);
      }

      if (session.status === 'completed') {
        trackEvent(env, request, 'status_poll', {
          provider: session.provider,
          result: 'completed',
          httpStatus: 200
        });
        return json({ status: 'completed', provider: session.provider });
      }

      await env.KV.put(sessionId, JSON.stringify(nextSession), { expirationTtl: sessionTtl(session, env) });
      trackEvent(env, request, 'status_poll', {
        provider: session.provider,
        result: 'pending',
        httpStatus: 200
      });
      return json({ status: 'pending', provider: session.provider });
    }

    if (url.pathname.startsWith('/claim/') && request.method === 'GET') {
      const sessionId = url.pathname.split('/').pop();
      if (!sessionId) {
        return badRequest('Missing sessionId');
      }

      const raw = await env.KV.get(sessionId);
      if (!raw) {
        return notFound('Session not found or expired');
      }

      const session = JSON.parse(raw);
      const checked = verifySignedRequest(session, sessionId, request, `/claim/${sessionId}`);
      if (!checked.ok) {
        trackEvent(env, request, 'claim_token', {
          provider: session.provider,
          result: 'error',
          httpStatus: checked.response.status,
          errorCode: checked.code || 'verification_failed'
        });
        return checked.response;
      }

      if (session.status === 'error') {
        await env.KV.delete(sessionId);
        trackEvent(env, request, 'claim_token', {
          provider: session.provider,
          result: 'session_error',
          httpStatus: 400,
          errorCode: safeString(session.error || 'callback_failed', 120)
        });
        return json({ status: 'error', provider: session.provider, error: session.error || 'callback_failed' }, 400);
      }

      if (session.status !== 'completed') {
        await env.KV.put(sessionId, JSON.stringify(checked.nextSession), { expirationTtl: sessionTtl(session, env) });
        trackEvent(env, request, 'claim_token', {
          provider: session.provider,
          result: 'pending',
          httpStatus: 200
        });
        return json({ status: 'pending', provider: session.provider });
      }

      await env.KV.delete(sessionId);
      trackEvent(env, request, 'claim_token', {
        provider: session.provider,
        result: 'ok',
        httpStatus: 200
      });
      return json({ status: 'completed', provider: session.provider, blob: session.blob });
    }

    trackEvent(env, request, 'not_found', {
      result: 'error',
      httpStatus: 404
    });
    return json({ error: 'Not found' }, 404);
  }
};
