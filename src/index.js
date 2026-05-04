const RATE_BUCKET = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 40;
const MAX_BODY_BYTES = 120_000;

function parseAllowedOrigins(value = '') {
  return String(value)
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);
}

function corsHeaders(origin, env) {
  const allowedOrigins = parseAllowedOrigins(env.ALLOWED_ORIGIN);
  const allowOrigin = allowedOrigins.length === 0
    ? origin || '*'
    : (allowedOrigins.includes(origin) ? origin : allowedOrigins[0]);

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function jsonResponse(body, status, origin, env) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
      ...corsHeaders(origin, env),
    },
  });
}

function getClientKey(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || 'unknown';
}

function checkRateLimit(clientKey) {
  const now = Date.now();
  const entry = RATE_BUCKET.get(clientKey) || { count: 0, resetAt: now + RATE_WINDOW_MS };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + RATE_WINDOW_MS;
  }
  entry.count += 1;
  RATE_BUCKET.set(clientKey, entry);
  if (RATE_BUCKET.size > 15000) {
    for (const [k, v] of RATE_BUCKET.entries()) {
      if (v.resetAt < now) RATE_BUCKET.delete(k);
    }
  }
  const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
  return {
    limited: entry.count > RATE_MAX_REQUESTS,
    remaining: Math.max(0, RATE_MAX_REQUESTS - entry.count),
    retryAfter,
  };
}

function isOriginAllowed(origin, env) {
  const allowedOrigins = parseAllowedOrigins(env.ALLOWED_ORIGIN);
  if (!origin) return true;
  if (allowedOrigins.length === 0) return true;
  return !!origin && allowedOrigins.includes(origin);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      if (!isOriginAllowed(origin, env)) {
        return jsonResponse({ error: 'Origin not allowed' }, 403, origin, env);
      }
      return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
    }

    const isHealthRoute = url.pathname === '/health' || url.pathname === '/api/health';
    const isAIRoute = url.pathname === '/ai' || url.pathname === '/api/ai';

    if (isHealthRoute) {
      return jsonResponse({ ok: true, service: 'flowday-ai' }, 200, origin, env);
    }

    if (!isAIRoute || request.method !== 'POST') {
      return jsonResponse({ error: 'Not found' }, 404, origin, env);
    }

    const contentLength = Number(request.headers.get('content-length') || '0');
    if (contentLength > MAX_BODY_BYTES) {
      return jsonResponse({ error: 'Request too large' }, 413, origin, env);
    }

    if (!isOriginAllowed(origin, env)) {
      return jsonResponse({ error: 'Origin not allowed' }, 403, origin, env);
    }

    const rate = checkRateLimit(getClientKey(request));
    if (rate.limited) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(rate.retryAfter),
          'X-RateLimit-Limit': String(RATE_MAX_REQUESTS),
          'X-RateLimit-Remaining': String(rate.remaining),
          'X-RateLimit-Reset': String(rate.retryAfter),
          ...corsHeaders(origin, env),
        },
      });
    }

    if (!env.OPENAI_API_KEY) {
      return jsonResponse({ error: 'OPENAI_API_KEY is not configured' }, 500, origin, env);
    }

    let payload;
    try {
      payload = await request.json();
    } catch {
      return jsonResponse({ error: 'Invalid JSON body' }, 400, origin, env);
    }

    const system = typeof payload.system === 'string' ? payload.system.trim() : '';
    const inputMessages = Array.isArray(payload.messages) ? payload.messages : [];
    const maxTokens = Math.max(64, Math.min(Number(payload.max_tokens) || 1024, 6000));
    const model = env.OPENAI_MODEL || 'gpt-4o-mini';

    const allowedRoles = new Set(['system', 'user', 'assistant']);
    const messages = [
      ...(system ? [{ role: 'system', content: system }] : []),
      ...inputMessages
        .filter(msg => msg && typeof msg.role === 'string' && typeof msg.content === 'string')
        .filter(msg => allowedRoles.has(msg.role))
        .map(msg => ({ role: msg.role, content: msg.content.slice(0, 12000) })),
    ];

    if (messages.length === 0) {
      return jsonResponse({ error: 'At least one message is required' }, 400, origin, env);
    }

    let upstream;
    try {
      upstream = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({
          model,
          messages,
          max_tokens: maxTokens,
        }),
      });
    } catch (error) {
      return jsonResponse({
        error: 'OpenAI upstream request failed',
        detail: error instanceof Error ? error.message : 'Unknown fetch error',
      }, 502, origin, env);
    }

    const rawText = await upstream.text();
    let data;
    try {
      data = rawText ? JSON.parse(rawText) : {};
    } catch {
      data = { raw: rawText };
    }

    if (!upstream.ok) {
      return jsonResponse({
        error: data?.error?.message || 'Upstream OpenAI request failed',
        status: upstream.status,
      }, upstream.status, origin, env);
    }

    const text = data?.choices?.[0]?.message?.content || '';
    return jsonResponse({
      model,
      response: text,
      choices: data?.choices || [],
      usage: data?.usage || null,
      rateLimit: {
        limit: RATE_MAX_REQUESTS,
        remaining: rate.remaining,
      },
    }, 200, origin, env);
  },
};
