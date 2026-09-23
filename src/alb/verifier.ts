import { decodeProtectedHeader, importSPKI, jwtVerify, type KeyLike } from 'jose';
import { ALB_DATA_HEADER, ALB_IDENTITY_HEADER, AlbIdentityError, type AlbIdentity } from './identity.js';

/**
 * Verifies the `x-amzn-oidc-data` JWT an ALB attaches to every authenticated request.
 *
 * In real AWS, the token is ES256-signed by the ALB, and its `kid` names a regional public key
 * served at `https://public-keys.auth.elb.<region>.amazonaws.com/<kid>` as a PEM SPKI document.
 * Verifying it - instead of just trusting the header - is what makes "the ALB already logged
 * this user in" a security boundary instead of a suggestion: a request that reaches this service
 * from anywhere other than the real load balancer cannot forge an identity, because it cannot
 * produce a signature the ALB's private key would produce.
 *
 * For training, `dev/fake-alb` generates its own ES256 keypair and serves the public half at
 * `http://localhost:4000/_fake_alb_public_keys/<kid>` in exactly this shape - so this class runs
 * its real verification path against a fake-but-structurally-identical key server, instead of a
 * bypass. That is the one piece of this repo most worth reading slowly.
 */
export interface AlbVerifierOptions {
  publicKeyEndpoint: string;
  clockToleranceSeconds?: number;
  keyCacheTtlMs?: number;
}

const KID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

interface CachedKey {
  key: KeyLike;
  expiresAt: number;
}

export class AlbDataVerifier {
  readonly #publicKeyEndpoint: string;
  readonly #clockToleranceSeconds: number;
  readonly #keyCacheTtlMs: number;
  readonly #cache = new Map<string, CachedKey>();

  constructor(options: AlbVerifierOptions) {
    this.#publicKeyEndpoint = options.publicKeyEndpoint.replace(/\/+$/, '');
    this.#clockToleranceSeconds = options.clockToleranceSeconds ?? 30;
    this.#keyCacheTtlMs = options.keyCacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  }

  async verify(headers: Record<string, string | string[] | undefined>): Promise<AlbIdentity> {
    const token = firstHeader(headers, ALB_DATA_HEADER);
    if (!token) {
      throw new AlbIdentityError(`missing ${ALB_DATA_HEADER} header - this route must sit behind an ALB authenticate-oidc rule`, 'missing_header');
    }

    let kid: string | undefined;
    try {
      kid = decodeProtectedHeader(token).kid;
    } catch (cause) {
      throw new AlbIdentityError(`${ALB_DATA_HEADER} is not a well-formed JWT`, 'malformed', { cause });
    }
    if (!kid || !KID_PATTERN.test(kid)) {
      throw new AlbIdentityError(`${ALB_DATA_HEADER} has a missing or unusable kid`, 'malformed');
    }

    const key = await this.#publicKey(kid);

    let payload: Record<string, unknown>;
    try {
      const result = await jwtVerify(token, key, {
        algorithms: ['ES256'],
        clockTolerance: this.#clockToleranceSeconds,
      });
      payload = result.payload;
    } catch (cause) {
      const code = (cause as { code?: string }).code === 'ERR_JWT_EXPIRED' ? 'expired' : 'signature';
      throw new AlbIdentityError(`${ALB_DATA_HEADER} failed verification`, code, { cause });
    }

    const headerSubject = firstHeader(headers, ALB_IDENTITY_HEADER);
    const subject = typeof payload.sub === 'string' ? payload.sub : headerSubject;
    if (!subject) {
      throw new AlbIdentityError('no subject present in the ALB identity headers', 'malformed');
    }

    return { subject, claims: payload, verified: true };
  }

  async #publicKey(kid: string): Promise<KeyLike> {
    const cached = this.#cache.get(kid);
    if (cached && cached.expiresAt > Date.now()) return cached.key;

    const url = `${this.#publicKeyEndpoint}/${encodeURIComponent(kid)}`;
    let response: Response;
    try {
      response = await fetch(url, { signal: AbortSignal.timeout(5000) });
    } catch (cause) {
      throw new AlbIdentityError(`could not reach the ALB public key endpoint ${url}`, 'key_unavailable', { cause });
    }
    if (!response.ok) {
      throw new AlbIdentityError(`ALB public key endpoint returned ${response.status} for kid ${kid}`, 'key_unavailable');
    }

    const pem = (await response.text()).trim();
    const key = await importSPKI(pem, 'ES256');
    this.#cache.set(kid, { key, expiresAt: Date.now() + this.#keyCacheTtlMs });
    return key;
  }
}

function firstHeader(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}
