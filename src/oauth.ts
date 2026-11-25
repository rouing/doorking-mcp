/**
 * @module oauth
 *
 * OAuth 2.1 Authorization Server provider for remote Streamable HTTP MCP, implementing the official
 * `@modelcontextprotocol/sdk` `OAuthServerProvider` interface and delegating user authentication and session
 * issuance/revocation strictly to `api/` over REST.
 */
import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';

interface PendingConsent {
  clientId: string;
  clientName: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  requestedScopes: string[];
  expiresAt: number;
}

interface IssuedCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  dksToken: string;
  user: string;
  scopes: string[];
  expiresAt: number;
}

interface VerifiedCacheEntry {
  info: AuthInfo;
  cachedUntil: number;
}

const MAX_CLIENTS = 200;
const CONSENT_TTL_MS = 10 * 60_000;
const CODE_TTL_MS = 5 * 60_000;
const VERIFY_CACHE_MS = 30_000;

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

export class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private readonly clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  registerClient(client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>): OAuthClientInformationFull {
    if (this.clients.size >= MAX_CLIENTS) {
      const oldest = this.clients.keys().next().value;
      if (oldest) this.clients.delete(oldest);
    }
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: `dkmcp_${crypto.randomBytes(12).toString('hex')}`,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    this.clients.set(full.client_id, full);
    return full;
  }
}

export interface DoorkingOAuthOptions {
  apiBaseUrl: string;
  defaultGate?: string;
  allowWorkingCopyWrites: boolean;
}

export class DoorkingOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new InMemoryClientsStore();
  private readonly apiBaseUrl: string;
  private readonly defaultGate: string;
  private readonly allowWorkingCopyWrites: boolean;
  private readonly pending = new Map<string, PendingConsent>();
  private readonly codes = new Map<string, IssuedCode>();
  private readonly tokenScopes = new Map<string, { scopes: string[]; clientId: string; user: string }>();
  private readonly verifyCache = new Map<string, VerifiedCacheEntry>();

  constructor(opts: DoorkingOAuthOptions) {
    this.apiBaseUrl = opts.apiBaseUrl.replace(/\/+$/, '');
    this.defaultGate = (opts.defaultGate || '').replace(/\D/g, '');
    this.allowWorkingCopyWrites = opts.allowWorkingCopyWrites;
  }

  private sweep(now = Date.now()): void {
    for (const [k, v] of this.pending) if (v.expiresAt <= now) this.pending.delete(k);
    for (const [k, v] of this.codes) if (v.expiresAt <= now) this.codes.delete(k);
    for (const [k, v] of this.verifyCache) if (v.cachedUntil <= now) this.verifyCache.delete(k);
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    this.sweep();
    const consentId = crypto.randomBytes(16).toString('hex');
    const requestedScopes = params.scopes?.length ? params.scopes : ['doorking:read'];
    this.pending.set(consentId, {
      clientId: client.client_id,
      clientName: client.client_name || client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      state: params.state,
      requestedScopes,
      expiresAt: Date.now() + CONSENT_TTL_MS,
    });
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(302, `/oauth/consent/${consentId}`);
  }

  private async fetchBrowserSession(cookieHeader: string | undefined): Promise<{ loggedIn: boolean; user?: string; sso: Array<{ id: string; name: string }> }> {
    try {
      const res = await fetch(`${this.apiBaseUrl}/api/session`, {
        headers: {
          Accept: 'application/json',
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        },
      });
      const data = await res.json().catch(() => ({})) as { loggedIn?: boolean; user?: string; sso?: Array<{ id: string; name: string }> };
      return {
        loggedIn: Boolean(res.ok && data.loggedIn && data.user),
        user: data.user,
        sso: Array.isArray(data.sso) ? data.sso : [],
      };
    } catch {
      return { loggedIn: false, sso: [] };
    }
  }

  /** Renders `GET /oauth/consent/:id`, reusing an existing same-origin DoorKing session or offering Passkey, SSO & password. */
  async renderConsentRequest(req: Request, res: Response): Promise<void> {
    this.sweep();
    const consentId = String(req.params.id || '');
    const consent = this.pending.get(consentId);
    if (!consent) {
      res.status(400).type('text/html; charset=utf-8').send('<h2>Authorization session expired. Restart sign-in from your MCP client.</h2>');
      return;
    }
    const forceSwitch = req.query.switch === '1';
    const session = await this.fetchBrowserSession(forceSwitch ? undefined : req.headers.cookie);
    res.setHeader('Cache-Control', 'no-store');
    res.type('text/html; charset=utf-8').send(
      this.renderConsentPage(consentId, consent.clientName, consent.requestedScopes, {
        signedInUser: session.loggedIn ? session.user : undefined,
        ssoProviders: session.sso,
      }),
    );
  }

  /** Handles `POST /oauth/approve` from the consent form: authenticates via existing session cookie or password and redirects with an OAuth code. */
  async handleConsentSubmit(req: Request, res: Response): Promise<void> {
    this.sweep();
    const body = (req.body || {}) as Record<string, string | undefined>;
    const consentId = String(body.consent_id || '');
    const consent = this.pending.get(consentId);
    if (!consent) {
      res.status(400).type('text/html; charset=utf-8').send('<h2>Authorization session expired. Restart sign-in from your MCP client.</h2>');
      return;
    }

    if (body.decision === 'deny') {
      this.pending.delete(consentId);
      const url = new URL(consent.redirectUri);
      url.searchParams.set('error', 'access_denied');
      if (consent.state) url.searchParams.set('state', consent.state);
      res.redirect(302, url.toString());
      return;
    }

    const grantStage = this.allowWorkingCopyWrites && body.allow_stage === '1';
    const grantedScopes = grantStage ? ['doorking:read', 'doorking:stage'] : ['doorking:read'];

    let mintedToken = '';
    let resolvedUser = '';

    if (body.use_session === '1') {
      let mintRes: globalThis.Response;
      try {
        mintRes = await fetch(`${this.apiBaseUrl}/api/session/mint-bearer`, {
          method: 'POST',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            ...(req.headers.cookie ? { Cookie: req.headers.cookie } : {}),
          },
          body: '{}',
        });
      } catch {
        res.status(502).type('text/html; charset=utf-8').send(this.renderConsentPage(consentId, consent.clientName, consent.requestedScopes, { error: 'Could not reach DoorKing API.' }));
        return;
      }
      const data = await mintRes.json().catch(() => ({})) as { error?: string; token?: string; user?: string };
      if (!mintRes.ok || !data.token || !data.user) {
        const session = await this.fetchBrowserSession(undefined);
        res.status(401).type('text/html; charset=utf-8').send(
          this.renderConsentPage(consentId, consent.clientName, consent.requestedScopes, {
            ssoProviders: session.sso,
            error: data.error || 'Your DoorKing session expired. Sign in below to continue.',
          }),
        );
        return;
      }
      mintedToken = data.token;
      resolvedUser = data.user;
    } else {
      const user = String(body.user || '').trim();
      const password = String(body.password || '');
      let sessionRes: globalThis.Response;
      try {
        sessionRes = await fetch(`${this.apiBaseUrl}/api/session`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Client-Auth': 'bearer',
          },
          body: JSON.stringify({ user, password }),
        });
      } catch {
        res.status(502).type('text/html; charset=utf-8').send(this.renderConsentPage(consentId, consent.clientName, consent.requestedScopes, { error: 'Could not reach DoorKing API.' }));
        return;
      }

      const data = await sessionRes.json().catch(() => ({})) as { error?: string; token?: string };
      if (!sessionRes.ok || !data.token) {
        const session = await this.fetchBrowserSession(undefined);
        res.status(401).type('text/html; charset=utf-8').send(
          this.renderConsentPage(consentId, consent.clientName, consent.requestedScopes, {
            ssoProviders: session.sso,
            error: data.error || 'Invalid username or password.',
          }),
        );
        return;
      }
      mintedToken = data.token;
      resolvedUser = user;
    }

    this.pending.delete(consentId);
    const code = crypto.randomBytes(24).toString('base64url');
    this.codes.set(code, {
      clientId: consent.clientId,
      redirectUri: consent.redirectUri,
      codeChallenge: consent.codeChallenge,
      dksToken: mintedToken,
      user: resolvedUser,
      scopes: grantedScopes,
      expiresAt: Date.now() + CODE_TTL_MS,
    });

    const redirect = new URL(consent.redirectUri);
    redirect.searchParams.set('code', code);
    if (consent.state) redirect.searchParams.set('state', consent.state);
    res.redirect(302, redirect.toString());
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    this.sweep();
    const entry = this.codes.get(authorizationCode);
    if (!entry || entry.clientId !== client.client_id) throw new Error('Invalid or expired authorization code');
    return entry.codeChallenge;
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<OAuthTokens> {
    this.sweep();
    const entry = this.codes.get(authorizationCode);
    if (!entry || entry.clientId !== client.client_id) throw new Error('Invalid or expired authorization code');
    this.codes.delete(authorizationCode);
    this.tokenScopes.set(entry.dksToken, { scopes: entry.scopes, clientId: client.client_id, user: entry.user });
    return {
      access_token: entry.dksToken,
      token_type: 'bearer',
      expires_in: 3600,
      scope: entry.scopes.join(' '),
    };
  }

  async exchangeRefreshToken(): Promise<OAuthTokens> {
    throw new Error('Refresh tokens are not enabled; re-authorize to obtain a new session token.');
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    this.sweep();
    const cached = this.verifyCache.get(token);
    if (cached && cached.cachedUntil > Date.now()) return cached.info;

    if (token.startsWith('dks_')) {
      const res = await fetch(`${this.apiBaseUrl}/api/session`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      });
      const data = await res.json().catch(() => ({})) as { loggedIn?: boolean; user?: string };
      if (!res.ok || !data.loggedIn || !data.user) throw new InvalidTokenError('Session token is invalid or expired');
      const meta = this.tokenScopes.get(token);
      const scopes = meta?.scopes || (this.allowWorkingCopyWrites ? ['doorking:read', 'doorking:stage'] : ['doorking:read']);
      const info: AuthInfo = {
        token,
        clientId: meta?.clientId || `user:${data.user}`,
        scopes,
        expiresAt: Math.floor(Date.now() / 1000) + 1800,
        extra: { user: data.user },
      };
      this.verifyCache.set(token, { info, cachedUntil: Date.now() + VERIFY_CACHE_MS });
      return info;
    }

    if (token.startsWith('dkg_')) {
      const res = await fetch(`${this.apiBaseUrl}/api/key-info`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      });
      const data = await res.json().catch(() => ({})) as {
        id?: string; name?: string; phone?: string; role?: string; scopes?: string[] | null;
      };
      if (!res.ok || !data.phone || !data.role) throw new InvalidTokenError('API key is invalid or expired');
      const hasWriteScope = !data.scopes || data.scopes.some((s) => s === 'directory:write' || s === 'settings:write' || s === 'gate:pull');
      const scopes = data.role === 'readonly' || !this.allowWorkingCopyWrites || !hasWriteScope
        ? ['doorking:read']
        : ['doorking:read', 'doorking:stage'];
      const info: AuthInfo = {
        token,
        clientId: `apikey:${data.id || data.phone}`,
        scopes,
        expiresAt: Math.floor(Date.now() / 1000) + 1800,
        extra: { role: data.role, gatePhone: data.phone, keyName: data.name || '' },
      };
      this.verifyCache.set(token, { info, cachedUntil: Date.now() + VERIFY_CACHE_MS });
      return info;
    }

    throw new InvalidTokenError('Unsupported or invalid bearer token');
  }

  async revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const token = request.token;
    this.tokenScopes.delete(token);
    this.verifyCache.delete(token);
    if (token.startsWith('dks_')) {
      await fetch(`${this.apiBaseUrl}/api/session`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {});
    }
  }

  private renderConsentPage(
    consentId: string,
    clientName: string,
    requestedScopes: string[],
    opts: { signedInUser?: string; ssoProviders?: Array<{ id: string; name: string }>; error?: string } = {},
  ): string {
    const { signedInUser, ssoProviders = [], error = '' } = opts;
    const stageChecked = this.allowWorkingCopyWrites && requestedScopes.includes('doorking:stage');
    const stageBox = this.allowWorkingCopyWrites
      ? `<label class="check"><input type="checkbox" name="allow_stage" value="1"${stageChecked ? ' checked' : ''}><span>Allow staging edits &amp; timed relay control</span></label>`
      : '';
    const ssoButtons = ssoProviders.map((p) => (
      `<button type="button" class="alt" data-sso="${escapeHtml(p.id)}">Sign in with ${escapeHtml(p.name)}</button>`
    )).join('');

    const bodyHtml = signedInUser
      ? `<div class="who">Signed in as <strong>${escapeHtml(signedInUser)}</strong> <a href="/oauth/consent/${escapeHtml(consentId)}?switch=1">Switch account</a></div>
  <input type="hidden" name="use_session" value="1">
  ${stageBox}
  <div class="row">
    <button class="no" type="submit" name="decision" value="deny" formnovalidate>Deny</button>
    <button class="ok" type="submit" name="decision" value="approve">Authorize</button>
  </div>`
      : `<div class="stack">
    <button type="button" class="ok" id="pkBtn">Sign in with passkey</button>
    ${ssoButtons}
  </div>
  <div class="sep"><span>or username &amp; password</span></div>
  <label for="u">Username or email</label><input id="u" name="user" type="text" autocomplete="username" required>
  <label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
  ${stageBox}
  <div class="row">
    <button class="no" type="submit" name="decision" value="deny" formnovalidate>Deny</button>
    <button class="ok" type="submit" name="decision" value="approve">Sign in &amp; Authorize</button>
  </div>`;

    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize DoorKing MCP</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px}
  .card{background:#1e293b;border-radius:16px;padding:24px;max-width:410px;width:100%;box-shadow:0 12px 32px rgba(0,0,0,.35)}
  h1{margin:0 0 8px;font-size:1.25rem} p{margin:0 0 16px;color:#94a3b8;font-size:.92rem;line-height:1.45}
  .who{background:#0f172a;border-radius:10px;padding:12px;margin-bottom:14px;font-size:.92rem;display:flex;justify-content:space-between;align-items:center;gap:8px}
  .who a{color:#38bdf8;text-decoration:none;font-size:.82rem}
  .stack{display:flex;flex-direction:column;gap:8px;margin-bottom:14px}
  .sep{display:flex;align-items:center;gap:10px;color:#64748b;font-size:.8rem;margin:14px 0}
  .sep:before,.sep:after{content:"";flex:1;height:1px;background:#334155}
  label{display:block;font-size:.85rem;margin-bottom:4px;color:#cbd5e1}
  input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#f8fafc;margin-bottom:12px;font-size:.95rem}
  .check{display:flex;gap:8px;align-items:flex-start;margin:10px 0 16px;font-size:.88rem;color:#cbd5e1}
  .err{background:#7f1d1d;color:#fecaca;padding:10px 12px;border-radius:10px;margin-bottom:12px;font-size:.88rem}
  .row{display:flex;gap:10px}
  button{flex:1;padding:11px;border:0;border-radius:999px;font-weight:600;cursor:pointer;font-size:.95rem}
  .ok{background:#0284c7;color:#fff} .alt{background:#334155;color:#f8fafc} .no{background:#334155;color:#e2e8f0}
  button:disabled{opacity:.6;cursor:wait}
</style></head>
<body><form class="card" method="POST" action="/oauth/approve">
  <h1>DoorKing Gate Manager</h1>
  <p><strong>${escapeHtml(clientName)}</strong> is requesting MCP access to your DoorKing account.</p>
  <div id="errBox" class="err" style="display:${error ? 'block' : 'none'}">${escapeHtml(error)}</div>
  <input type="hidden" name="consent_id" value="${escapeHtml(consentId)}">
  ${bodyHtml}
</form>
<script>
(() => {
  const errBox = document.getElementById('errBox');
  const showErr = (m) => { errBox.textContent = m; errBox.style.display = 'block'; };
  const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
  const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');

  const pkBtn = document.getElementById('pkBtn');
  if (pkBtn) {
    if (!window.PublicKeyCredential) { pkBtn.style.display = 'none'; }
    pkBtn.addEventListener('click', async () => {
      pkBtn.disabled = true; errBox.style.display = 'none';
      try {
        const r1 = await fetch('/api/passkey/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        const opts = await r1.json();
        if (!r1.ok) throw new Error(opts.error || 'Passkey sign-in unavailable');
        const publicKey = {
          ...opts,
          challenge: b64uToBuf(opts.challenge),
          allowCredentials: (opts.allowCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
        };
        const cred = await navigator.credentials.get({ publicKey });
        if (!cred) throw new Error('Passkey sign-in cancelled');
        const payload = {
          id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
          response: {
            authenticatorData: bufToB64u(cred.response.authenticatorData),
            clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            signature: bufToB64u(cred.response.signature),
            userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
          },
          clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
        };
        const r2 = await fetch('/api/passkey/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ response: payload }) });
        const d2 = await r2.json();
        if (!r2.ok) throw new Error(d2.error || 'Passkey sign-in failed');
        window.location.href = '/oauth/consent/${escapeHtml(consentId)}';
      } catch (e) {
        if (e && e.name !== 'NotAllowedError') showErr(e.message || String(e));
        pkBtn.disabled = false;
      }
    });
  }

  document.querySelectorAll('[data-sso]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      btn.disabled = true; errBox.style.display = 'none';
      try {
        document.cookie = 'dk_return_to=' + encodeURIComponent('/oauth/consent/${escapeHtml(consentId)}') + '; Path=/; Max-Age=600; SameSite=Lax; Secure';
        const r = await fetch('/api/sso/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider: btn.dataset.sso }) });
        const d = await r.json();
        if (!r.ok || !d.url) throw new Error(d.error || 'Could not start SSO');
        window.location.href = d.url;
      } catch (e) {
        showErr(e.message || String(e));
        btn.disabled = false;
      }
    });
  });
})();
</script></body></html>`;
  }
}
