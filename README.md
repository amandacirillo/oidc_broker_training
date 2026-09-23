# OIDC Broker Training

A standalone, runnable reimplementation of an "ALB-relayed identity broker" pattern: an
Application Load Balancer authenticates a user against your org's identity provider (Entra,
Okta, Google...) via its built-in `authenticate-oidc` listener action, and a small service behind
it re-issues that identity as a standards-compliant OIDC provider for other applications to
consume - with zero login prompt of its own, because the ALB already did that part.

This is a training project. Every AWS ID in it (VPC, ACM certificate, account number) is a
placeholder. It does **not** contain any proprietary code, business logic, or real infrastructure
values from the system that inspired it - only the same architectural pattern, written from
scratch, with a runnable demo you can poke at.

## Why this pattern exists

A load balancer's `authenticate-oidc` action is a genuinely useful piece of infrastructure: point
it at your org's IdP, and every request that reaches your target group already carries a verified
identity, with no auth code in your application at all. The catch is that identity only exists as
three non-standard HTTP headers scoped to *that one ALB* - `x-amzn-oidc-data`,
`x-amzn-oidc-identity`, `x-amzn-oidc-accesstoken`. Nothing else can use it directly.

An **OIDC broker** solves that by sitting behind the authenticated ALB and doing two things:

1. **Verify** the ALB's assertion is genuine - it's a real ES256-signed JWT, and AWS publishes
   the ALB's public key at a predictable URL, so this is a real cryptographic check, not just
   trusting a header because it showed up.
2. **Re-issue** that identity as a real OIDC Authorization Code flow, so any relying party that
   speaks standard OIDC - not just "things behind this specific ALB" - can consume it.

## The architecture, and the one part that's easy to get wrong

```
                 ┌─────────────────────────┐
   Browser ─────▶│   Public ALB (4000)     │  authenticate-oidc on /authorize, /interaction/*
                 │  (Entra-protected)      │  everything else forwarded unauthenticated
                 └───────────┬─────────────┘
                              │  x-amzn-oidc-data (signed JWT)
                              ▼
                 ┌─────────────────────────┐
                 │   Broker (Koa + oidc-   │  verifies the JWT, maps claims,
                 │   provider), port 3000  │  checks an authorization policy,
                 └───────────┬─────────────┘  issues its OWN tokens
                              │
                 ┌───────────▼─────────────┐
   Relying     ─▶│  Internal ALB (4001)    │  /token, /me (userinfo) ONLY - no auth action
   party's ALB   │  (back-channel only)    │  called server-to-server, never by a browser
                 └─────────────────────────┘
```

The browser-facing ALB needs **two listener rules, ordered by priority**: one with
`authenticate-oidc`, covering only the paths that actually need a logged-in user
(`/authorize`, `/interaction/*`); another, lower-priority, unauthenticated rule for everything
else (`/jwks`, `/.well-known/*`, `/healthz`). Get the priority numbers backwards and the
authenticated rule silently never matches.

The **second ALB** is the part that looks redundant until you've been burned by it: `/token` and
`/me` (userinfo) are called by the *relying party's own load balancer nodes*, server-to-server,
never by a browser. If you put those paths behind the same `authenticate-oidc` rule, the ALB
responds with a redirect-to-login instead of a token - which a server-to-server HTTP client
doesn't know what to do with. And even with the routing fixed, sending that traffic through the
*public* internet-facing ALB can still fail intermittently, because the calling ALB's own node
IPs were never expected to hit a public ingress path meant for browsers. The fix in the real
system - and the one modeled here - is a **second, internal-only ALB** dedicated to just those two
paths, so that traffic never has to leave the VPC or pass through an ALB doing browser-oriented
authentication at all.

## What's simplified from a production broker

| Real system | This training repo |
|---|---|
| Redis/DynamoDB session + token storage | In-memory `MemoryAdapter` (`src/adapters/memory-adapter.ts`) - same `Adapter` interface, swappable |
| Dynamic client registration (RFC 7591) | One static demo client (`demo-rp` / `demo-rp-secret`) |
| RBAC-driven authorization scope | A simple email-domain allow/deny policy (`src/policy/authorization-policy.ts`) |
| Keys persisted in Secrets Manager | Ephemeral JWKS generated on boot (`src/keys/keystore.ts`) |
| Real Entra tenant | `dev/fake-alb` - a local harness that signs real ES256 JWTs and serves a real public-key endpoint, so the broker's actual verification code runs unmodified |

None of the source files here were copied from the proprietary project that inspired this
pattern - the verifier, claims mapper, and provider configuration were written independently
against the public `jose` / `oidc-provider` APIs and the architecture described above.

## Running it

Everything below is HTTP calls only - **no browser needed**, which is itself the point: a real
user's browser would follow these exact redirects automatically and never see a prompt, because
the ALB already authenticated them. Scripting it this way lets you actually assert on that
"zero visible prompt" property.

```bash
npm install

# Terminal 1: the broker itself
npm run broker            # http://localhost:3000

# Terminal 2: the fake ALB harness (public port 4000, internal back-channel port 4001)
npm run fake-alb

# Terminal 3: drive the full Authorization Code + PKCE flow
npm run demo-rp -- alice  # a demo user whose email passes the allowlist policy
npm run demo-rp -- bob    # a demo user whose email does NOT pass - watch it get denied
```

A successful `alice` run prints the authorization code, the token response (access + ID token),
and the claims returned from `/me` (the userinfo endpoint) - all fetched through the *internal*
back-channel ALB on port 4001, exactly as a relying party's own infrastructure would.

## Tests

```bash
npm test          # vitest: claims mapping + real ES256 signature verification
npm run typecheck # tsc --noEmit across src/, dev/, and tests/
```

`tests/verifier.test.ts` spins up a throwaway local HTTP server acting as a fake ALB public-key
endpoint and signs real JWTs against it, so the actual cryptographic verification path in
`src/alb/verifier.ts` is exercised - not mocked.

## CDK

`cdk/lib/oidc_broker_stack.ts` sketches the dual-ALB + listener-rule-priority infrastructure
described above (ECS Fargate service, two `ApplicationLoadBalancer`s, an `authenticate-oidc`
listener action backed by a placeholder Cognito user pool standing in for a real IdP). All
VPC/account/certificate IDs are placeholders - `cdk/bin/app.ts` documents which values you'd swap
in to `cdk synth` it against your own sandbox account. `cdk synth`ing for real requires live AWS
credentials (for the `ec2.Vpc.fromLookup` context lookup); `npm run typecheck` inside `cdk/` is
the offline-friendly correctness check, same as in the sibling `cicd_stack_training` repo.

## Exercises

1. **Break the listener priority on purpose.** In `cdk/lib/oidc_broker_stack.ts`, swap the
   `priority` values of `AuthenticatedBrowserPaths` and `UnauthenticatedPublicPaths` and explain
   in a sentence why `/authorize` would then never get an IdP redirect.
2. **Add a second demo relying party.** Register a second static client in
   `src/provider/configuration.ts` with a different `redirect_uris` entry, and get `dev/demo-rp`
   to drive a flow against it via an environment variable or CLI flag.
3. **Make the authorization policy claims-aware instead of email-only.** Extend
   `AuthorizationPolicy` to also check a `groups` claim (you'll need to add it to
   `dev/fake-alb`'s `DEMO_USERS` and `src/alb/claims.ts`'s claim mapping first).
4. **Simulate key rotation.** Give `FakeAlb` a second keypair and a `kid` of
   `fake-alb-signing-key-2`; make `signIdentity` alternate between them, and confirm
   `AlbDataVerifier`'s per-`kid` cache correctly fetches and verifies against whichever key
   signed a given token.
5. **Replace `MemoryAdapter` with a file-backed one.** Swap the `Map`-based storage for
   something that persists to disk (e.g. a JSON file), and observe that a broker restart no
   longer invalidates in-flight interactions - this is the same shape of change as swapping in a
   real Redis adapter.
