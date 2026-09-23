import { interactionPolicy, type Configuration, type KoaContextWithOIDC } from 'oidc-provider';
import { MemoryAdapter } from '../adapters/memory-adapter.js';
import { getAccountClaims } from '../adapters/account-store.js';
import { filterClaimsByScope, SUPPORTED_SCOPES } from '../alb/claims.js';

/**
 * The demo relying party this training repo ships (dev/demo-rp) - pre-registered statically so
 * you can run the whole flow with no separate registration step. The real broker supports RFC
 * 7591 dynamic client registration too (see docs/onboarding.md in the source project); that is
 * intentionally left out here to keep the surface area focused on the ALB-relay mechanism.
 */
const DEMO_CLIENTS: Configuration['clients'] = [
  {
    client_id: 'demo-rp',
    client_secret: 'demo-rp-secret',
    redirect_uris: ['http://localhost:5000/callback'],
    response_types: ['code'],
    grant_types: ['authorization_code'],
    token_endpoint_auth_method: 'client_secret_basic',
  },
];

// This broker never shows its own consent screen: trust was already established the moment the
// ALB verified the user against Entra, and re-prompting "does this app get to see your name and
// email" would be theater the org's SSO policy already decided. Dropping the 'consent' prompt
// from the default policy means oidc-provider treats every requested scope as pre-authorized
// once login succeeds, instead of looping back into a second interaction for consent.
const policy = interactionPolicy.base();
policy.remove('consent');

export function buildConfiguration(jwks: { keys: Array<Record<string, unknown>> }): Configuration {
  return {
    clients: DEMO_CLIENTS,
    jwks: jwks as Configuration['jwks'],

    // Every model (Grant, AuthorizationCode, AccessToken, Interaction, Session...) is persisted
    // through the same in-memory adapter, keyed by model name - see MemoryAdapter.
    adapter: MemoryAdapter,

    // No `devInteractions` and no login/consent forms: the whole point of the ALB-relay pattern
    // is that the user was already authenticated by the ALB, so the interaction is resolved
    // programmatically the instant the ALB's assertion is verified. See routes/interaction.ts.
    interactions: {
      policy,
      url(_ctx: KoaContextWithOIDC, interaction: { uid: string }) {
        return `/interaction/${interaction.uid}`;
      },
    },

    scopes: [...SUPPORTED_SCOPES],
    claims: {
      openid: ['sub'],
      profile: ['name', 'given_name', 'family_name', 'preferred_username'],
      email: ['email', 'email_verified'],
    },

    findAccount(_ctx: KoaContextWithOIDC, sub: string) {
      const claims = getAccountClaims(sub);
      if (!claims) return undefined;
      return {
        accountId: sub,
        async claims(_use: string, scope: string) {
          return filterClaimsByScope(claims, scope.split(' '));
        },
      };
    },

    features: {
      devInteractions: { enabled: false },
      userinfo: { enabled: true },
      introspection: { enabled: true },
      revocation: { enabled: true },
    },

    // A relying party's own load balancer calls /token and /userinfo directly, not through a
    // browser - see the README's "why the back channel has its own load balancer" section. PKCE
    // is still required on /token regardless, which is why dev/demo-rp generates a code_verifier.
    pkce: { required: () => true },

    cookies: {
      keys: ['training-only-cookie-secret-do-not-reuse'],
    },

    ttl: {
      Interaction: 300,
      AuthorizationCode: 60,
      AccessToken: 3600,
      IdToken: 3600,
    },
  };
}
