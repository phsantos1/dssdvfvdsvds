import { randomBytes, createHash, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';

const { MAPS_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, PANEL_PASSWORD } = process.env;
const host = process.env.VERCEL_PROJECT_PRODUCTION_URL;
const origin = 'https://' + host;
const redirect = origin + '/api/callback';
const configured = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
const key = createHash('sha256').update('radar-local/session/' + (PANEL_PASSWORD || '')).digest();

function encode(session) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(session)), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
}

function decode(cookie) {
  try {
    const bytes = Buffer.from(cookie || '', 'base64url');
    const cipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
    cipher.setAuthTag(bytes.subarray(12, 28));
    const data = JSON.parse(Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]));
    return data.last > Date.now() - 7200000 ? data : null;
  } catch { return null; }
}
const token = () => randomBytes(32).toString('base64url');
const clean = (v, max) => typeof v === 'string' ? v.trim().slice(0, max) : '';
const line = (v, max) => clean(v, max).replace(/[\r\n\x00-\x1f]/g, ' ');
const matches = (a, b) => typeof a === 'string' && typeof b === 'string' &&
  Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));

async function readJson(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return JSON.parse(req.body);
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > 24000) throw new Error('Pedido demasiado grande.');
  }
  return JSON.parse(body);
}

async function google(url, options, label) {
  const res = await fetch(url, { ...options, signal: AbortSignal.timeout(18000) });
  if (!res.ok) throw new Error(label + ' devolveu o código ' + res.status + '. Verifique a configuração e tente novamente.');
  return res.json();
}

const senders = {
  PT: { locale:'pt-PT', country:'Portugal', fallback:'Lisboa', category:'cabeleireiros' },
  US: { locale:'en-US', country:'United States', fallback:'Miami, FL', category:'barbershops' }
};

function signature(us, name, address) {
  return us
    ? '\n\n' + name + '\n' + address + '\nCommercial message. To stop receiving emails from me, reply “unsubscribe”.'
    : '\n\n' + name + '\n' + address + '\nMensagem comercial. Para deixar de receber emails, responda com “remover”.';
}

export default async function handler(req, res, action) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  const json = (data, status = 200) => {
    save();
    res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
  };
  let session;
  const save = () => {
    if (session) res.setHeader('Set-Cookie', '__Host-radar=' + encode(session) + '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=7200');
  };
  const back = () => { save(); res.writeHead(303, { Location:'/' }); res.end(); };
  if (!host || !PANEL_PASSWORD || PANEL_PASSWORD.length < 24) return json({error:'Configure PANEL_PASSWORD com pelo menos 24 caracteres e ative as variáveis de sistema da Vercel.'}, 503);
  if (req.headers.host !== host) return json({error:'Abra o domínio de produção ' + origin}, 403);
  const login = 'Basic ' + Buffer.from('radar:' + PANEL_PASSWORD).toString('base64');
  if (!matches(req.headers.authorization, login)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Radar Local", charset="UTF-8"');
    return json({error:'Acesso privado.'}, 401);
  }
  const url = new URL(req.url, origin);
  const path = '/api/' + action;
  if (req.method === 'GET' && action === 'login') return back();
  const cookie = req.headers.cookie?.match(/(?:^|; )__Host-radar=([\w-]+)/)?.[1];
  session = decode(cookie) || { csrf:token(), sent:[] };
  session.last = Date.now();
  try {
    if (req.method === 'GET' && path === '/api/status') {
      const error = session.error;
      delete session.error;
      return json({ maps:Boolean(MAPS_KEY), gmail:configured, connected:session.expires > Date.now(), csrf:session.csrf, error });
    }
    if (req.method === 'GET' && path === '/api/callback') {
      const pending = session.pending;
      delete session.pending;
      if (!pending || Date.now() - pending.time > 600000 || !matches(url.searchParams.get('state'), pending.state) || !url.searchParams.get('code')) {
        session.error = 'A autorização foi cancelada ou expirou.';
        return back();
      }
      try {
        const auth = await google('https://oauth2.googleapis.com/token', {
          method:'POST', body:new URLSearchParams({
            code:url.searchParams.get('code'), client_id:GOOGLE_CLIENT_ID, client_secret:GOOGLE_CLIENT_SECRET,
            redirect_uri:redirect, grant_type:'authorization_code', code_verifier:pending.verifier
          })
        }, 'Google OAuth');
        if (!auth.scope?.split(' ').includes('https://www.googleapis.com/auth/gmail.send')) throw new Error('Autorize o envio pelo Gmail para continuar.');
        session.access = auth.access_token;
        session.expires = Date.now() + (auth.expires_in - 30) * 1000;
      } catch (error) { session.error = error.message; }
      return back();
    }
    if (req.method !== 'POST') return json({error:'Página não encontrada.'}, 404);
    if (req.headers.origin !== origin || !matches(req.headers['x-csrf-token'], session.csrf)) return json({error:'Sessão inválida. Recarregue a página.'}, 403);
    const data = await readJson(req);
    if (path === '/api/connect') {
      if (!configured) return json({error:'Configure as credenciais OAuth nas variáveis de ambiente.'}, 400);
      const pending = session.pending = { state:token(), verifier:token(), time:Date.now() };
      const query = new URLSearchParams({
        client_id:GOOGLE_CLIENT_ID, redirect_uri:redirect, response_type:'code',
        scope:'https://www.googleapis.com/auth/gmail.send', state:pending.state, prompt:'select_account',
        code_challenge:createHash('sha256').update(pending.verifier).digest('base64url'), code_challenge_method:'S256'
      });
      return json({url:'https://accounts.google.com/o/oauth2/v2/auth?' + query});
    }
    if (path === '/api/disconnect') {
      delete session.access;
      delete session.expires;
      delete session.pending;
      return json({ok:true});
    }
    if (path === '/api/search') {
      const region = Object.hasOwn(senders, data.region) ? senders[data.region] : null;
      if (!region) return json({error:'Escolha Portugal ou Estados Unidos.'}, 400);
      if (!MAPS_KEY) return json({error:'Configure MAPS_KEY nas variáveis de ambiente para pesquisar.'}, 400);
      const result = await google('https://places.googleapis.com/v1/places:searchText', {
        method:'POST', headers:{
          'Content-Type':'application/json', 'X-Goog-Api-Key':MAPS_KEY,
          'X-Goog-FieldMask':'places.displayName,places.formattedAddress,places.websiteUri,places.googleMapsUri,places.addressComponents,places.businessStatus,places.attributions,nextPageToken'
        },
        body:JSON.stringify({
          textQuery: (line(data.category, 90) || region.category) + ' in ' + (line(data.city, 110) || region.fallback) + ', ' + region.country,
          regionCode:data.region, languageCode:region.locale, pageSize:20,
          ...(clean(data.next, 4000) ? { pageToken:clean(data.next, 4000) } : {})
        })
      }, 'Google Places');
      const places = (result.places || []).filter(place => !place.websiteUri && place.businessStatus === 'OPERATIONAL' &&
        place.addressComponents?.some(part => part.types.includes('country') && part.shortText === data.region))
        .map(place => ({name:place.displayName?.text, address:place.formattedAddress, maps:place.googleMapsUri, attributions:place.attributions || []}));
      return json({places, next:result.nextPageToken});
    }
    if (path === '/api/send') {
      if (!session.access || !(session.expires > Date.now())) return json({error:'Ligue o Gmail para enviar.'}, 401);
      const to = clean(data.to, 254).toLowerCase();
      const subject = line(data.subject, 140);
      const message = clean(data.message, 5000);
      const name = line(data.sender, 150);
      const address = line(data.address, 240);
      if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(to) ||
          !subject || !message || !name || !address || data.consent !== true || !Object.hasOwn(senders, data.region)) {
        return json({error:'Preencha os dados e confirme a autorização do destinatário.'}, 400);
      }
      if (session.sent.includes(createHash('sha256').update(to).digest('base64url'))) return json({error:'Já existe um envio para este endereço nesta sessão.'}, 409);
        const body = Buffer.from(message + signature(data.region === 'US', name, address)).toString('base64').match(/.{1,76}/g).join('\r\n');
        const encoded = (value) => (value.match(/.{1,10}/gu) || []).map(part => '=?UTF-8?B?' + Buffer.from(part).toString('base64') + '?=').join('\r\n ');
        const raw = Buffer.from(['To: ' + to, 'Subject: ' + encoded(subject), 'MIME-Version: 1.0',
          'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', body].join('\r\n')).toString('base64url');
        const sent = await google('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
          method:'POST', headers:{ Authorization:'Bearer ' + session.access, 'Content-Type':'application/json' },
          body:JSON.stringify({raw})
        }, 'Gmail');
        session.sent = [...session.sent.slice(-9), createHash('sha256').update(to).digest('base64url')];
        return json({id:sent.id});
    }
    return json({error:'Página não encontrada.'}, 404);
  } catch (error) { return json({error:error.name === 'TimeoutError' ? 'O serviço demorou a responder. Se estava a enviar, confira os Enviados antes de repetir.' : error.message}, 400); }
}

