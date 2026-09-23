import { createHash, randomBytes } from 'node:crypto';

/**
 * Drives the full Authorization Code + PKCE flow purely with HTTP requests - no browser, no
 * headless Chrome. That's not a shortcut for the demo: it is the actual point being demonstrated.
 * A real user's browser would follow the same redirects automatically and never see a login
 * screen, because the ALB already authenticated them before the request ever reached the broker.
 * Scripting it this way makes that "zero visible prompt" property something you can assert on.
 *
 * One thing a real browser gives you for free that a bare `fetch` does not: a cookie jar.
 * oidc-provider tracks the in-flight authorization request via an `_interaction_resume` session
 * cookie between "redirect to /interaction/:uid" and "redirect back to /auth/:uid/resume once
 * login is done" - so this script keeps a tiny cookie jar of its own across the hops below.
 */
const FAKE_ALB_PUBLIC = process.env.FAKE_ALB_PUBLIC ?? 'http://localhost:4000';
const FAKE_ALB_INTERNAL = process.env.FAKE_ALB_INTERNAL ?? 'http://localhost:4001';
const CLIENT_ID = 'demo-rp';
const CLIENT_SECRET = 'demo-rp-secret';
const REDIRECT_URI = 'http://localhost:5000/callback';

function base64url(input: Buffer): string {
  return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

class CookieJar {
  private readonly cookies = new Map<string, string>();

  capture(response: Response): void {
    for (const setCookie of response.headers.getSetCookie?.() ?? []) {
      const [pair] = setCookie.split(';');
      const eq = pair.indexOf('=');
      if (eq === -1) continue;
      this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  header(): string {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function follow(jar: CookieJar, url: URL): Promise<Response> {
  const response = await fetch(url, { redirect: 'manual', headers: { cookie: jar.header() } });
  jar.capture(response);
  return response;
}

async function run(): Promise<void> {
  const userKey = process.argv[2] ?? 'alice';
  const jar = new CookieJar();

  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const state = base64url(randomBytes(8));

  const authorizeUrl = new URL(`${FAKE_ALB_PUBLIC}/auth`);
  authorizeUrl.searchParams.set('as', userKey);
  authorizeUrl.searchParams.set('client_id', CLIENT_ID);
  authorizeUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', 'openid profile email');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', codeChallenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  console.log(`--> GET ${authorizeUrl.pathname}${authorizeUrl.search}  (as fake ALB user '${userKey}')`);
  let response = await follow(jar, authorizeUrl);
  let hops = 0;
  while (response.status >= 300 && response.status < 400 && hops < 10) {
    const location = response.headers.get('location');
    if (!location) break;
    console.log(`<-- ${response.status} redirect to ${location}`);
    if (location.startsWith(REDIRECT_URI)) break;
    const nextUrl = new URL(location, FAKE_ALB_PUBLIC);
    response = await follow(jar, nextUrl);
    hops += 1;
  }

  const finalLocation = response.headers.get('location');
  const callbackUrl = finalLocation ? new URL(finalLocation, REDIRECT_URI) : undefined;
  const code = callbackUrl?.searchParams.get('code');
  const returnedState = callbackUrl?.searchParams.get('state');

  if (!code) {
    console.error('No authorization code received. Was the identity rejected by policy? Full response:');
    console.error(response.status, await response.text().catch(() => ''));
    process.exitCode = 1;
    return;
  }
  if (returnedState !== state) {
    throw new Error('state mismatch - possible CSRF, aborting');
  }
  console.log(`<-- authorization code received (state verified)`);

  // The token exchange goes to the INTERNAL back-channel ALB - a relying party's own ALB nodes
  // call /token server-to-server, never through the browser-facing/authenticated one.
  const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const tokenResponse = await fetch(`${FAKE_ALB_INTERNAL}/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${basicAuth}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    }),
  });
  const tokens = (await tokenResponse.json()) as Record<string, unknown>;
  if (!tokenResponse.ok) {
    console.error('Token exchange failed:', tokens);
    process.exitCode = 1;
    return;
  }
  console.log('--> POST /token (via internal back-channel ALB, port 4001)');
  console.log('<-- tokens:', JSON.stringify(tokens, null, 2));

  const userinfoResponse = await fetch(`${FAKE_ALB_INTERNAL}/me`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  const userinfo = await userinfoResponse.json();
  console.log('--> GET /me aka userinfo (via internal back-channel ALB, port 4001)');
  console.log('<-- claims:', JSON.stringify(userinfo, null, 2));
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
