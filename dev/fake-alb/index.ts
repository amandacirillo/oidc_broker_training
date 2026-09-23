import Koa from 'koa';
import Router from '@koa/router';
import { FakeAlb, DEMO_USERS } from './keys.js';
import { ALB_ACCESS_TOKEN_HEADER, ALB_DATA_HEADER, ALB_IDENTITY_HEADER } from '../../src/alb/identity.js';

/**
 * Simulates the two-ALB / two-listener-rule split described in the broker's README, which is
 * "the part that is easy to get wrong":
 *
 *   PUBLIC_PORT (4000)   plays the internet-facing, Entra-protected ALB.
 *     - /interaction/*  and /auth*          -> browser-facing rule: inject the signed identity
 *                                              headers (as if Entra had just signed someone in),
 *                                              THEN forward.
 *     - everything else (/jwks, /.well-known/*, /healthz) -> forward with no headers at all,
 *                                              same as the real ALB's second, unauthenticated rule.
 *
 *   INTERNAL_PORT (4001) plays the broker's own internal back-channel ALB.
 *     - only /token and /me (the userinfo endpoint) are forwarded, still with NO identity
 *       headers (a relying party's load balancer calls these server-to-server; there is no
 *       browser session to assert here - these are authenticated by client secret / bearer token
 *       instead).
 *     - anything else -> 404, matching the real internal ALB's ingress being that narrow.
 *
 * Get this split backwards (e.g. put an authenticate-oidc-shaped rule in front of /token) and the
 * symptom in real AWS is a relying party's ALB reporting HTTP 561 - see the README for why.
 */
const BROKER_ORIGIN = process.env.BROKER_ORIGIN ?? 'http://localhost:3000';
const PUBLIC_PORT = Number(process.env.FAKE_ALB_PUBLIC_PORT ?? 4000);
const INTERNAL_PORT = Number(process.env.FAKE_ALB_INTERNAL_PORT ?? 4001);

async function proxy(ctx: Koa.Context, extraHeaders: Record<string, string> = {}): Promise<void> {
  const url = new URL(ctx.querystring ? `${ctx.path}?${ctx.querystring}` : ctx.path, BROKER_ORIGIN);
  const hasBody = ctx.method !== 'GET' && ctx.method !== 'HEAD';
  const response = await fetch(url, {
    method: ctx.method,
    headers: { ...(ctx.headers as Record<string, string>), ...extraHeaders, host: undefined as unknown as string },
    // Needed for the /token POST: koa's raw request stream is passed straight through as the
    // outgoing fetch body instead of buffering it, matching what a real load balancer does.
    body: hasBody ? (ctx.req as unknown as string) : undefined,
    duplex: hasBody ? 'half' : undefined,
    redirect: 'manual',
  } as RequestInit);
  ctx.status = response.status;
  for (const [key, value] of response.headers.entries()) {
    if (key.toLowerCase() === 'content-encoding' || key.toLowerCase() === 'set-cookie') continue;
    ctx.set(key, value);
  }
  // Set-Cookie is special-cased: oidc-provider sets a signed cookie as a *pair* of headers
  // (e.g. `_interaction_resume` + `_interaction_resume.sig`). Headers.entries() would otherwise
  // return them, but ctx.set() overwrites same-name headers - losing all but the last cookie -
  // so each one is appended individually instead.
  for (const cookie of response.headers.getSetCookie()) {
    ctx.append('set-cookie', cookie);
  }
  ctx.body = Buffer.from(await response.arrayBuffer());
}

async function main(): Promise<void> {
  const fakeAlb = await FakeAlb.create();

  // --- Public / browser-facing ALB ---
  const publicApp = new Koa();
  const publicRouter = new Router();

  publicRouter.get('/_fake_alb_public_keys/:kid', (ctx) => {
    const pem = fakeAlb.publicKeyPemFor(ctx.params.kid);
    if (!pem) {
      ctx.status = 404;
      return;
    }
    ctx.type = 'text/plain';
    ctx.body = pem;
  });

  publicRouter.all(/^\/(interaction|auth)(\/.*)?$/, async (ctx) => {
    // A real user only presents credentials to Entra once; after that, Entra's own SSO session
    // cookie is what lets every subsequent hop (including the redirect back into /interaction and
    // /auth/:uid resume, neither of which carry the original query string) know who's signed in.
    // This fake_alb_session cookie plays that same role for the demo.
    const requestedUser = typeof ctx.query.as === 'string' ? ctx.query.as : undefined;
    const userKey = requestedUser ?? ctx.cookies.get('fake_alb_session') ?? 'alice';
    const user = DEMO_USERS[userKey];
    if (!user) {
      ctx.status = 400;
      ctx.body = { error: `unknown fake user '${userKey}'. Known users: ${Object.keys(DEMO_USERS).join(', ')}` };
      return;
    }
    if (requestedUser) {
      ctx.cookies.set('fake_alb_session', requestedUser, { httpOnly: true, sameSite: 'lax' });
    }
    const token = await fakeAlb.signIdentity(user);
    await proxy(ctx, {
      [ALB_DATA_HEADER]: token,
      [ALB_IDENTITY_HEADER]: user.sub,
      [ALB_ACCESS_TOKEN_HEADER]: 'fake-upstream-entra-access-token',
    });
  });

  // Anything else on the public ALB (jwks, well-known, healthz...) is forwarded WITHOUT
  // identity headers - matching the real ALB's second, unauthenticated listener rule.
  publicRouter.all(/.*/, async (ctx) => {
    await proxy(ctx);
  });

  publicApp.use(publicRouter.routes());
  publicApp.listen(PUBLIC_PORT, () => console.log(`[fake-alb:public]   http://localhost:${PUBLIC_PORT}  (simulates the Entra-protected, browser-facing ALB)`));

  // --- Internal back-channel ALB ---
  const internalApp = new Koa();
  const internalRouter = new Router();
  internalRouter.all(/^\/(token|me)$/, async (ctx) => {
    await proxy(ctx);
  });
  internalRouter.all(/.*/, (ctx) => {
    ctx.status = 404;
    ctx.body = { error: 'not_found', error_description: 'the internal back-channel ALB only forwards /token and /me (userinfo)' };
  });
  internalApp.use(internalRouter.routes());
  internalApp.listen(INTERNAL_PORT, () => console.log(`[fake-alb:internal] http://localhost:${INTERNAL_PORT}  (simulates the internal back-channel ALB; /token + /userinfo only)`));
}

main().catch((error) => {
  console.error('[fake-alb] failed to start:', error);
  process.exit(1);
});
