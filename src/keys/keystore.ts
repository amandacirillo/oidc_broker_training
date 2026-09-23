import { exportJWK, generateKeyPair } from 'jose';

/**
 * The broker's OWN signing keys - used to sign the ID tokens / access tokens it issues to relying
 * parties. Do not confuse these with the ALB's keys in alb/verifier.ts: those verify a JWT the
 * ALB gave *us*; these sign the JWTs *we* give someone else. Two different key pairs, two
 * different trust directions.
 *
 * In production these would be generated once and persisted (e.g. Secrets Manager), so that a
 * restart doesn't invalidate every token a relying party is still holding. For training, we just
 * generate a fresh ephemeral RSA keypair on boot - simplest possible thing that lets you see a
 * real JWKS document and real signed ID tokens.
 */
export async function generateBrokerJwks(): Promise<{ keys: Array<Record<string, unknown>> }> {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(privateKey);
  return { keys: [{ ...jwk, use: 'sig', alg: 'RS256', kid: 'broker-signing-key-1' }] };
}
