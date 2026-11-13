import handler from './handler.mjs';
const actions = new Set(['status','search','connect','disconnect','send','callback','login']);
export default function gateway(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const action = url.searchParams.get('action') || url.pathname.split('/').at(-1);
  if (!actions.has(action)) { res.statusCode = 404; return res.end(); }
  return handler(req, res, action);
}
