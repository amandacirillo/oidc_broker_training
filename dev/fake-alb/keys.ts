import { exportSPKI, generateKeyPair, SignJWT, type KeyLike } from 'jose';

/**
 * Stands in for AWS: generates a real ES256 keypair, serves the public half in the same shape
 * ALB's real key-server does (a bare PEM at /_fake_alb_public_keys/<kid>), and signs assertions
 * with the private half - so src/alb/verifier.ts's real signature-checking code runs against
 * this, unmodified.
 */
export interface FakeUser {
  sub: string;
  name: string;
  given_name: string;
  family_name: string;
  email: string;
}

export const DEMO_USERS: Record<string, FakeUser> = {
  alice: {
    sub: 'entra-oid-alice-0001',
    name: 'Alice Anderson',
    given_name: 'Alice',
    family_name: 'Anderson',
    email: 'alice@example.com',
  },
  bob: {
    sub: 'entra-oid-bob-0002',
    name: 'Bob Brown',
    given_name: 'Bob',
    family_name: 'Brown',
    email: 'bob@not-allowed.com',
  },
};

const KID = 'fake-alb-signing-key-1';

export class FakeAlb {
  private constructor(
    private readonly privateKey: KeyLike,
    private readonly publicKeyPem: string,
  ) {}

  static async create(): Promise<FakeAlb> {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const pem = await exportSPKI(publicKey);
    return new FakeAlb(privateKey, pem);
  }

  get kid(): string {
    return KID;
  }

  publicKeyPemFor(kid: string): string | undefined {
    return kid === KID ? this.publicKeyPem : undefined;
  }

  /** Signs an x-amzn-oidc-data-shaped JWT asserting `user` is logged in, exactly like a real ALB would. */
  async signIdentity(user: FakeUser): Promise<string> {
    return new SignJWT({ ...user })
      .setProtectedHeader({ alg: 'ES256', kid: KID, signer: 'arn:aws:elasticloadbalancing:local:000000000000:loadbalancer/app/fake-alb/0000' })
      .setSubject(user.sub)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(this.privateKey);
  }
}
