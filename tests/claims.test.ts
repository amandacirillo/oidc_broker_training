import { describe, expect, it } from 'vitest';
import { filterClaimsByScope, mapAlbIdentityToClaims } from '../src/alb/claims.js';
import type { AlbIdentity } from '../src/alb/identity.js';

describe('mapAlbIdentityToClaims', () => {
  it('maps a full ALB identity payload to standard OIDC claims', () => {
    const identity: AlbIdentity = {
      subject: 'entra-oid-alice-0001',
      verified: true,
      claims: {
        sub: 'entra-oid-alice-0001',
        name: 'Alice Anderson',
        given_name: 'Alice',
        family_name: 'Anderson',
        email: 'alice@example.com',
      },
    };

    const claims = mapAlbIdentityToClaims(identity);

    expect(claims).toMatchObject({
      sub: 'entra-oid-alice-0001',
      name: 'Alice Anderson',
      given_name: 'Alice',
      family_name: 'Anderson',
      preferred_username: 'alice@example.com',
      email: 'alice@example.com',
      email_verified: true,
    });
  });

  it('tolerates a sparse identity, falling back only to what is present', () => {
    const identity: AlbIdentity = {
      subject: 'entra-oid-bob-0002',
      verified: true,
      claims: { sub: 'entra-oid-bob-0002' },
    };

    const claims = mapAlbIdentityToClaims(identity);

    expect(claims.sub).toBe('entra-oid-bob-0002');
    expect(claims.email).toBeUndefined();
    expect(claims.email_verified).toBeUndefined();
  });
});

describe('filterClaimsByScope', () => {
  const fullClaims = {
    sub: 'entra-oid-alice-0001',
    name: 'Alice Anderson',
    given_name: 'Alice',
    family_name: 'Anderson',
    preferred_username: 'alice@example.com',
    email: 'alice@example.com',
    email_verified: true,
  };

  it('always includes sub, even with no scopes granted', () => {
    expect(filterClaimsByScope(fullClaims, [])).toEqual({ sub: fullClaims.sub });
  });

  it('includes only claims covered by the granted scopes', () => {
    const filtered = filterClaimsByScope(fullClaims, ['openid', 'email']);
    expect(filtered).toEqual({
      sub: fullClaims.sub,
      email: fullClaims.email,
      email_verified: fullClaims.email_verified,
    });
  });

  it('includes profile claims when profile scope is granted', () => {
    const filtered = filterClaimsByScope(fullClaims, ['openid', 'profile']);
    expect(filtered).toEqual({
      sub: fullClaims.sub,
      name: fullClaims.name,
      given_name: fullClaims.given_name,
      family_name: fullClaims.family_name,
      preferred_username: fullClaims.preferred_username,
    });
  });
});
