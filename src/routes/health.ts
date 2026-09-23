import Router from '@koa/router';

export function buildHealthRouter(): Router {
  const router = new Router();
  router.get('/healthz', (ctx) => {
    ctx.body = { status: 'ok' };
  });
  router.get('/readyz', (ctx) => {
    // The real broker also pings Redis here. We have nothing external to check, but the route
    // exists so a real deployment's readiness probe path never has to change.
    ctx.body = { status: 'ok' };
  });
  return router;
}
