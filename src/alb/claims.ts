import type { AlbIdentity } from './identity.js';

/**
 * Maps the raw claim vocabulary carried inside `x-amzn-oidc-data` (Entra-shaped, in the real
 * system) to the standard OIDC claims a relying party expects. Keeping this mapping in one
 * explicit place - instead of just forwarding the upstream payload verbatim - means a relying
 * party codes against *this* contract, not whatever the identity provider happens to emit today.
 */
export const SCOPE_CLAIMS = {
  openid: ['sub'],
  profile: ['name', 'given_name', 'family_name', 'preferred_username'],
  email: ['email', 'email_verified'],
} as const satisfies Record<string, readonly string[]>;

export type BrokerScope = keyof typeof SCOPE_CLAIMS;
export const SUPPORTED_SCOPES: readonly BrokerScope[] = Object.keys(SCOPE_CLAIMS) as BrokerScope[];

export interface BrokerAccountClaims {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  [claim: string]: unknown;
}

export function mapAlbIdentityToClaims(identity: AlbIdentity): BrokerAccountClaims {
  const raw = identity.claims;
  const claims: BrokerAccountClaims = { sub: identity.subject };

  assign(claims, 'name', str(raw.name));
  assign(claims, 'given_name', str(raw.given_name));
  assign(claims, 'family_name', str(raw.family_name));
  assign(claims, 'preferred_username', str(raw.preferred_username) ?? str(raw.email));
  assign(claims, 'email', str(raw.email));
  if (claims.email) {
    claims.email_verified = true;
  }
  return claims;
}

function assign<K extends keyof BrokerAccountClaims>(
  target: BrokerAccountClaims,
  key: K,
  value: BrokerAccountClaims[K] | undefined,
): void {
  if (value !== undefined) target[key] = value;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** Filters a claim set down to only what the granted scopes cover, per SCOPE_CLAIMS above. */
export function filterClaimsByScope(claims: BrokerAccountClaims, grantedScopes: Iterable<string>): BrokerAccountClaims {
  const allowed = new Set<string>(['sub']);
  for (const scope of grantedScopes) {
    for (const claim of SCOPE_CLAIMS[scope as BrokerScope] ?? []) allowed.add(claim);
  }

  const filtered: BrokerAccountClaims = { sub: claims.sub };
  for (const [key, value] of Object.entries(claims)) {
    if (allowed.has(key) && value !== undefined) filtered[key] = value;
  }
  return filtered;
}
