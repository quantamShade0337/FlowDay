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
      ...corsHeaders(origin, env),
    },
  });
}

function isOriginAllowed(origin, env) {
  const allowedOrigins = parseAllowedOrigins(env.ALLOWED_ORIGIN);
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

    if (url.pathname === '/health') {
      return jsonResponse({ ok: true, service: 'flowday-ai' }, 200, origin, env);
    }

    if (url.pathname !== '/ai' || request.method !== 'POST') {
      return jsonResponse({ error: 'Not found' }, 404, origin, env);
    }

    if (!isOriginAllowed(origin, env)) {
      return jsonResponse({ error: 'Origin not allowed' }, 403, origin, env);
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

    const messages = [
      ...(system ? [{ role: 'system', content: system }] : []),
      ...inputMessages
        .filter(msg => msg && typeof msg.role === 'string' && typeof msg.content === 'string')
        .map(msg => ({ role: msg.role, content: msg.content })),
    ];

    if (messages.length === 0) {
      return jsonResponse({ error: 'At least one message is required' }, 400, origin, env);
    }

    const upstream = await fetch('https://api.openai.com/v1/chat/completions', {
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
    }, 200, origin, env);
  },
};
