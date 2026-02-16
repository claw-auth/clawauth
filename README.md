# clawauth (multi-provider, async OAuth for agents)

Cloudflare Worker + CLI for ephemeral OAuth dead-drop with async agent workflows.

- `/init` creates session in KV and returns both `shortAuthUrl` and `authUrl`
- `/callback` validates signed `state`, exchanges code for token, encrypts with `nacl.box`
- `/status/:sessionId` returns `pending|completed|error` (no token payload)
- `/claim/:sessionId` returns encrypted blob once completed and deletes server session
- `/providers` returns supported providers
- `/<provider>/<sessionId>` short redirect URL to long provider OAuth URL

## Supported providers

- `notion`, `github`, `discord`, `linear`, `airtable`, `todoist`, `asana`, `trello`, `dropbox`, `digitalocean`, `slack`, `gitlab`, `reddit`, `figma`, `spotify`, `bitbucket`, `box`, `calendly`, `fathom`, `twitch`

## Install

```bash
npm install
```

## Publish/CLI usage

After publish:

```bash
npx clawauth login start notion
```

CLI help:

```bash
clawauth --help
clawauth login --help
clawauth explain
```

Global install:

```bash
npm i -g clawauth
clawauth login start notion
```

## Async command model

Start and return immediately:

```bash
clawauth login start notion --ttl 3600
```

Check later:

```bash
clawauth login status <sessionId>
```

Machine-readable output:

```bash
clawauth login status <sessionId> --json
```

List all local sessions (grouped by provider, with live status check):

```bash
clawauth sessions
```

Claim later (decrypt + store refresh token):

```bash
clawauth login claim <sessionId>
```

Read stored tokens later from keychain:

```bash
clawauth token list
clawauth token get notion
clawauth token env notion
```

For shell export usage:

```bash
eval "$(clawauth token env notion)"
```

Optional blocking mode:

```bash
clawauth login wait <sessionId>
```

Provider discovery:

```bash
clawauth providers
```

## TTL

- Default session TTL: `3600` seconds (1 hour)
- Configurable per request via `--ttl`
- Server clamps TTL to `60..86400` seconds
- Optional server default override with worker var `SESSION_TTL_SECONDS`

## Worker config

`/Users/hagen/Projects/skills/clawauth/wrangler.toml` uses custom domain:

- `auth.clawauth.app`

Global worker settings:

- `PUBLIC_BASE_URL=https://auth.clawauth.app`

Required worker secrets:

- `STATE_SIGNING_SECRET`
- For each provider:
  - `<PROVIDER>_CLIENT_ID`
  - `<PROVIDER>_CLIENT_SECRET`
  - optional `<PROVIDER>_REDIRECT_URI`
  - optional `<PROVIDER>_AUTH_URL`
  - optional `<PROVIDER>_TOKEN_URL`

Example for Notion:

```bash
npx wrangler secret put NOTION_CLIENT_ID
npx wrangler secret put NOTION_CLIENT_SECRET
npx wrangler secret put NOTION_REDIRECT_URI
```

## Security model (current)

- Signed OAuth `state` via HMAC, including provider binding
- Signed polling/claim requests (`timestamp|sessionId|method|path|nonce`)
- Nonce replay protection
- Per-session polling rate limits
- E2E encrypted token blob (`nacl.box`)
- Token only returned by `/claim`; KV deleted on successful claim
- Refresh token stored in system keychain by CLI
- Local session cryptographic material stored in keychain until claim/delete

## Open source hygiene

- Repository can be public.
- Never commit: `*_CLIENT_SECRET`, `STATE_SIGNING_SECRET`, API tokens.
- Keep runtime secrets only in Cloudflare Worker secrets.
