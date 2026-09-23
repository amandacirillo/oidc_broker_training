import Router from '@koa/router';
import type Provider from 'oidc-provider';
import { AlbDataVerifier } from '../alb/verifier.js';
import { mapAlbIdentityToClaims } from '../alb/claims.js';
import { AlbIdentityError } from '../alb/identity.js';
import { saveAccountClaims } from '../adapters/account-store.js';
import type { AuthorizationPolicy } from '../policy/authorization-policy.js';

/**
 * The zero-prompt interaction resolver.
 *
 * A normal OIDC provider would render a login form here. This one never does: by the time a
 * request reaches this route, the ALB in front of it has ALREADY authenticated the user (that is
 * what makes this a "broker" and not a full identity provider) - so all this route has to do is:
 *
 *   1. verify the ALB's signed assertion is genuine (AlbDataVerifier)
 *   2. map its claims into the broker's standard shape (mapAlbIdentityToClaims)
 *   3. ask the authorization policy whether this identity is allowed through at all
 *   4. stash the claims where findAccount can find them later, and tell oidc-provider login is
 *      done - which redirects the browser straight back into the authorization flow it started.
 *
 * No template, no button, no visible step for the user at all.
 */
export function buildInteractionRouter(provider: Provider, verifier: AlbDataVerifier, policy: AuthorizationPolicy): Router {
  const router = new Router();

  router.get('/interaction/:uid', async (ctx) => {
    let identity;
    try {
      identity = await verifier.verify(ctx.headers as Record<string, string | string[] | undefined>);
    } catch (error) {
      if (error instanceof AlbIdentityError) {
        ctx.status = 401;
        ctx.body = { error: error.code, error_description: error.message };
        return;
      }
      throw error;
    }

    const claims = mapAlbIdentityToClaims(identity);
    const decision = policy.evaluate(claims);
    if (!decision.allow) {
      ctx.status = 403;
      ctx.body = { error: 'access_denied', error_description: decision.reason };
      return;
    }

    saveAccountClaims(claims);

    // We disabled the 'consent' prompt entirely (see provider/configuration.ts) because this
    // broker doesn't show its own consent screen. But oidc-provider still requires *something*
    // to record which scopes/claims a client is allowed to receive - that's a Grant. Normally the
    // consent screen builds it interactively; here we build it programmatically from whatever the
    // client asked for, in the same login step, since the ALB assertion already implies the org
    // trusts this client to see these claims.
    const interactionDetails = await provider.interactionDetails(ctx.req, ctx.res);
    const { params } = interactionDetails;
    const grant = new provider.Grant({
      accountId: claims.sub,
      clientId: String(params.client_id),
    });
    grant.addOIDCScope(String(params.scope ?? 'openid'));
    const grantId = await grant.save();

    const result = { login: { accountId: claims.sub }, consent: { grantId } };
    const redirectTo = await provider.interactionResult(ctx.req, ctx.res, result, { mergeWithLastSubmission: false });
    ctx.status = 200;
    ctx.body = { redirect_to: redirectTo };
    // A real browser flow would 302 here; we return the URL as JSON too so a script (or the demo
    // relying party) driving this without a browser can follow it explicitly and show its work.
    ctx.redirect(redirectTo);
  });

  return router;
}
