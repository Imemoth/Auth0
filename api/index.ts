import type { VercelRequest, VercelResponse } from '@vercel/node';

const json = (res: VercelResponse, status: number, body: unknown) => {
  res.status(status).setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const path = req.url?.split('?')[0] ?? '/';

  if (path === '/health' || path === '/api/index') {
    return json(res, 200, {
      ok: true,
      runtime: 'vercel-serverless',
      service: 'identity',
      time: new Date().toISOString()
    });
  }

  return json(res, 501, {
    error: {
      code: 'AUTH_API_TEMPORARILY_DISABLED_ON_VERCEL',
      message: 'The Vercel serverless function is alive. Auth routes will be re-enabled after runtime validation.'
    },
    path,
    method: req.method
  });
}
