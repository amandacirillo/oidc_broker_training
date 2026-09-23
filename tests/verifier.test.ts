import { exportSPKI, generateKeyPair, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { AlbDataVerifier } from '../src/alb/verifier.js';
import { AlbIdentityError } from '../src/alb/identity.js';

/**
 * Exercises the real verification code path against an in-process fake key server, using
 * Node's own `fetch` - the same mechanism dev/fake-alb relies on, just without needing a second
 * process for a unit test.
 */
async function withFakeKeyServer(
  run: (opts: { sign: (payload: Record<string, unknown>, kid?: string) => Promise<string>; endpoint: string }) => Promise<void>,
): Promise<void> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const pem = await exportSPKI(publicKey);
  const kid = 'test-kid-1';

  const http = await import('node:http');
  const httpServer = http.createServer((req, res) => {
    const requestedKid = req.url?.split('/').pop();
    if (requestedKid === kid) {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(pem);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((resolve) => httpServer.listen(0, resolve));
  const address = httpServer.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const endpoint = `http://127.0.0.1:${port}`;

  try {
    await run({
      endpoint,
      sign: (payload, signKid = kid) =>
        new SignJWT(payload).setProtectedHeader({ alg: 'ES256', kid: signKid }).setSubject(String(payload.sub ?? 'test-subject')).setIssuedAt().setExpirationTime('5m').sign(privateKey),
    });
  } finally {
    httpServer.close();
  }
}

describe('AlbDataVerifier', () => {
  it('verifies a genuinely signed assertion and returns its claims', async () => {
    await withFakeKeyServer(async ({ sign, endpoint }) => {
      const token = await sign({ sub: 'entra-oid-alice-0001', email: 'alice@example.com' });
      const verifier = new AlbDataVerifier({ publicKeyEndpoint: endpoint });

      const identity = await verifier.verify({
        'x-amzn-oidc-data': token,
        'x-amzn-oidc-identity': 'entra-oid-alice-0001',
      });

      expect(identity.subject).toBe('entra-oid-alice-0001');
      expect(identity.claims.email).toBe('alice@example.com');
      expect(identity.verified).toBe(true);
    });
  });

  it('rejects a request with no ALB assertion header at all', async () => {
    const verifier = new AlbDataVerifier({ publicKeyEndpoint: 'http://127.0.0.1:1' });
    await expect(verifier.verify({})).rejects.toThrow(AlbIdentityError);
  });

  it('rejects an assertion referencing a kid the key server does not have', async () => {
    await withFakeKeyServer(async ({ sign, endpoint }) => {
      const token = await sign({ sub: 'entra-oid-alice-0001' }, 'wrong-kid');
      const verifier = new AlbDataVerifier({ publicKeyEndpoint: endpoint });
      await expect(verifier.verify({ 'x-amzn-oidc-data': token })).rejects.toThrow(AlbIdentityError);
    });
  });

  it('rejects a token signed by an untrusted key entirely', async () => {
    await withFakeKeyServer(async ({ endpoint }) => {
      const { privateKey: otherKey } = await generateKeyPair('ES256', { extractable: true });
      const forgedToken = await new SignJWT({ sub: 'entra-oid-mallory-0666' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-kid-1' })
        .setSubject('entra-oid-mallory-0666')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(otherKey);

      const verifier = new AlbDataVerifier({ publicKeyEndpoint: endpoint });
      await expect(verifier.verify({ 'x-amzn-oidc-data': forgedToken })).rejects.toThrow(AlbIdentityError);
    });
  });
});
