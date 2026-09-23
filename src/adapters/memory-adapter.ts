import type { Adapter, AdapterPayload } from 'oidc-provider';

/**
 * A from-scratch in-memory implementation of oidc-provider's Adapter interface, standing in for
 * the real broker's Redis-backed adapter. Every model (grants, authorization codes, access
 * tokens, sessions, interactions...) round-trips through here.
 *
 * This is deliberately NOT production-appropriate: state disappears on restart, and nothing is
 * evicted proactively (we do respect `expiresIn` on read, which is enough for a demo). In
 * production you would swap this one class for a Redis (or DynamoDB) adapter without touching
 * anything else in the provider - that swappability is the whole reason the Adapter interface
 * exists.
 */
export class MemoryAdapter implements Adapter {
  private static readonly stores = new Map<string, Map<string, StoredPayload>>();

  constructor(private readonly name: string) {
    if (!MemoryAdapter.stores.has(name)) {
      MemoryAdapter.stores.set(name, new Map());
    }
  }

  private get store(): Map<string, StoredPayload> {
    return MemoryAdapter.stores.get(this.name)!;
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
    const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : undefined;
    this.store.set(id, { payload, expiresAt });
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    return this.#read(id);
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    return this.#findBy((payload) => payload.userCode === userCode);
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    return this.#findBy((payload) => payload.uid === uid);
  }

  async consume(id: string): Promise<void> {
    const entry = this.store.get(id);
    if (entry) entry.payload.consumed = Math.floor(Date.now() / 1000);
  }

  async destroy(id: string): Promise<void> {
    this.store.delete(id);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    for (const [id, entry] of this.store.entries()) {
      if (entry.payload.grantId === grantId) this.store.delete(id);
    }
  }

  #read(id: string): AdapterPayload | undefined {
    const entry = this.store.get(id);
    if (!entry) return undefined;
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.store.delete(id);
      return undefined;
    }
    return entry.payload;
  }

  #findBy(predicate: (payload: AdapterPayload) => boolean): AdapterPayload | undefined {
    for (const [id, entry] of this.store.entries()) {
      if (entry.expiresAt && entry.expiresAt < Date.now()) {
        this.store.delete(id);
        continue;
      }
      if (predicate(entry.payload)) return entry.payload;
    }
    return undefined;
  }
}

interface StoredPayload {
  payload: AdapterPayload;
  expiresAt?: number;
}
