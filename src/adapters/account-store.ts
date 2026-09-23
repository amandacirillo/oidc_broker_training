import type { BrokerAccountClaims } from '../alb/claims.js';

/**
 * Where a resolved account's claims live between "the interaction route verified the ALB
 * assertion and decided to log this subject in" and "oidc-provider's findAccount asks for that
 * subject's claims later, possibly on a completely different request/response cycle (e.g. a
 * /userinfo call from the relying party's back channel, minutes later)".
 *
 * The real broker's AccountStore is backed by Redis so this survives process restarts and scales
 * across tasks; this in-memory version is the training-sized stand-in - same interface, same
 * reason for existing, easy to swap later.
 */
const accounts = new Map<string, BrokerAccountClaims>();

export function saveAccountClaims(claims: BrokerAccountClaims): void {
  accounts.set(claims.sub, claims);
}

export function getAccountClaims(sub: string): BrokerAccountClaims | undefined {
  return accounts.get(sub);
}
