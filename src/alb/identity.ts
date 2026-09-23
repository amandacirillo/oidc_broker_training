/**
 * The identity an Application Load Balancer's `authenticate-oidc` action has already
 * established for the caller, once we've verified it.
 *
 * This mirrors AWS ALB's real behavior: when a listener rule has an `authenticate-oidc`
 * action, the ALB itself talks to the identity provider (Entra, Okta, Google...), and once
 * the user is signed in the ALB attaches three headers to every request it forwards to the
 * target:
 *
 *   x-amzn-oidc-data         a signed JWT with the user's claims (ES256)
 *   x-amzn-oidc-identity     the subject, duplicated outside the JWT for convenience
 *   x-amzn-oidc-accesstoken  the raw upstream access token, if you need to call the IdP back
 *
 * The broker's whole reason to exist is: verify that JWT, then re-issue the identity as
 * standards-compliant OIDC to someone else. See alb/verifier.ts for the "verify" half and
 * alb/claims.ts for the "re-issue" half.
 */
export interface AlbIdentity {
  subject: string;
  claims: Record<string, unknown>;
  /** True unless verification was explicitly skipped (see verifier.ts's insecure dev mode). */
  verified: boolean;
}

export class AlbIdentityError extends Error {
  constructor(
    message: string,
    readonly code: 'missing_header' | 'malformed' | 'signature' | 'expired' | 'untrusted_signer' | 'key_unavailable',
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'AlbIdentityError';
  }
}

export const ALB_DATA_HEADER = 'x-amzn-oidc-data';
export const ALB_IDENTITY_HEADER = 'x-amzn-oidc-identity';
export const ALB_ACCESS_TOKEN_HEADER = 'x-amzn-oidc-accesstoken';
