import Koa from 'koa';
import mount from 'koa-mount';
import Provider from 'oidc-provider';
import { pathToFileURL } from 'node:url';
import { buildConfiguration } from './provider/configuration.js';
import { buildInteractionRouter } from './routes/interaction.js';
import { buildHealthRouter } from './routes/health.js';
import { AlbDataVerifier } from './alb/verifier.js';
import { EmailDomainAllowlistPolicy } from './policy/authorization-policy.js';
import { generateBrokerJwks } from './keys/keystore.js';

export interface BrokerConfig {
  issuer: string;
  port: number;
  albPublicKeyEndpoint: string;
  allowedEmailDomains: string[];
}

export async function createBrokerApp(config: BrokerConfig): Promise<Koa> {
  const jwks = await generateBrokerJwks();
  const oidcConfig = buildConfiguration(jwks);
  const provider = new Provider(config.issuer, oidcConfig);
  provider.proxy = true;

  const verifier = new AlbDataVerifier({ publicKeyEndpoint: config.albPublicKeyEndpoint });
  const policy = new EmailDomainAllowlistPolicy(config.allowedEmailDomains);

  const app = new Koa();

  // Health checks are unauthenticated by design - they're what the ALB target group itself
  // polls, and it cannot present its own ALB-issued assertion to check on itself.
  app.use(buildHealthRouter().routes());
  app.use(buildInteractionRouter(provider, verifier, policy).routes());

  // Everything oidc-provider itself understands (/auth, /token, /userinfo, /jwks,
  // /.well-known/openid-configuration, /introspection, /revocation...) is mounted last, as a
  // sub-application, so our own routes above always get first refusal on a path.
  app.use(mount(provider.app));

  return app;
}

async function main(): Promise<void> {
  const port = Number(process.env.PORT ?? 3000);
  const app = await createBrokerApp({
    issuer: process.env.BROKER_ISSUER ?? `http://localhost:${port}`,
    port,
    albPublicKeyEndpoint: process.env.ALB_PUBLIC_KEY_ENDPOINT ?? 'http://localhost:4000/_fake_alb_public_keys',
    allowedEmailDomains: (process.env.ALLOWED_EMAIL_DOMAINS ?? 'example.com').split(',').map((d) => d.trim()),
  });

  app.listen(port, () => {
    console.log(`[broker] listening on http://localhost:${port}`);
  });
}

// Only auto-start when this file is the process entrypoint (tsx src/index.ts), not when it's
// imported by tests. Compared as file:// URLs (not raw path strings) because on Windows
// process.argv[1] uses backslashes while import.meta.url is always a forward-slash file URL.
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error('[broker] failed to start:', error);
    process.exit(1);
  });
}
