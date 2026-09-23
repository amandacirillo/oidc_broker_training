import type { BrokerAccountClaims } from '../alb/claims.js';

/**
 * The pluggable "should this identity actually be let in" hook. The real broker asks Wilbur's
 * RBAC service here; this training version just checks an email-domain allowlist, but the shape
 * - a function that looks at claims and returns allow/deny - is the point to copy.
 */
export interface AuthorizationDecision {
  allow: boolean;
  reason?: string;
}

export interface AuthorizationPolicy {
  evaluate(claims: BrokerAccountClaims): AuthorizationDecision;
}

export class EmailDomainAllowlistPolicy implements AuthorizationPolicy {
  constructor(private readonly allowedDomains: readonly string[]) {}

  evaluate(claims: BrokerAccountClaims): AuthorizationDecision {
    if (this.allowedDomains.length === 0) {
      return { allow: true };
    }
    const email = claims.email;
    if (!email) {
      return { allow: false, reason: 'no email claim present to check against the allowlist' };
    }
    const domain = email.split('@')[1]?.toLowerCase();
    const allowed = domain !== undefined && this.allowedDomains.includes(domain);
    return allowed ? { allow: true } : { allow: false, reason: `email domain '${domain}' is not on the allowlist` };
  }
}
