// Proof Gatekeeper agent for zkVerify Agent Games (Cloudflare Worker).
// Env: AGENT_GAMES_HMAC_SECRET (secret, from the Agent Games dashboard "Rotate Secret").
// Optional KV binding: SEEN (proof-reuse memory + idempotent responses). Falls back to memory.
const enc = new TextEncoder();

async function hmacHex(secret, text) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(text));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function timingEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
const mem = new Map();
async function kvGet(env, k) {
  if (env.SEEN) return env.SEEN.get(k);
  return mem.has(k) ? mem.get(k) : null;
}
async function kvPut(env, k, v) {
  if (env.SEEN) { try { await env.SEEN.put(k, v, { expirationTtl: 2592000 }); } catch (e) { /* keep serving */ } }
  else mem.set(k, v);
}
async function signed(text, secret) {
  return new Response(text, {
    status: 200,
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': await hmacHex(secret, text) },
  });
}

// All seven documented traps, checked in the event page's order. Fail closed.
async function decide(env, input) {
  const low = (x) => String(x ?? '').toLowerCase();
  const num = (x) => { try { return BigInt(String(x)); } catch (e) { return null; } };
  if (!input || !input.proof_vk || !input.registered_vk || low(input.proof_vk) !== low(input.registered_vk))
    return ['REJECT', 'VK_SUBSTITUTION'];
  const bal = num(input.public_balance), min = num(input.minimum);
  if (bal === null || min === null || bal < min) return ['REJECT', 'THRESHOLD_MISMATCH'];
  if (input.proof_tx && (await kvGet(env, 'tx:' + low(input.proof_tx)))) return ['REJECT', 'PROOF_REUSED'];
  const cur = num(input.current_block), exp = num(input.expiry_block);
  if (cur === null || exp === null || cur > exp) return ['REJECT', 'EXPIRED_CONDITION'];
  if (!input.recipient || low(input.recipient) !== low(input.condition_recipient))
    return ['REJECT', 'RECIPIENT_MISMATCH'];
  const amt = num(input.amount), cap = num(input.max_transfer);
  if (amt === null || cap === null || amt > cap) return ['REJECT', 'AMOUNT_OVERFLOW'];
  if (input.proof_tx) await kvPut(env, 'tx:' + low(input.proof_tx), '1');
  return ['APPROVE', 'VALID_CONDITION'];
}

export default {
  async fetch(req, env) {
    if (req.method !== 'POST') return new Response('not found', { status: 404 });
    const secret = env.AGENT_GAMES_HMAC_SECRET;
    if (!secret) return new Response('secret not configured', { status: 500 });
    const raw = await req.text();
    const given = (req.headers.get('x-agent-games-signature') || '').toLowerCase();
    if (!timingEq(given, await hmacHex(secret, raw))) return new Response('bad signature', { status: 401 });
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return new Response('bad json', { status: 400 }); }
    if (msg.type === 'agent-games.preflight.v1') {
      return signed(JSON.stringify({ ok: true, protocolVersion: 'v1' }), secret);
    }
    if (msg.type === 'agent-games.proof-gatekeeper.v1') {
      if (msg.task_id) {
        const cached = await kvGet(env, 'resp:' + msg.task_id);
        if (cached) return signed(cached, secret);
      }
      const [decision, reason] = await decide(env, msg.input || {});
      const body = JSON.stringify({ decision, reason_code: reason, proof_tx: (msg.input || {}).proof_tx });
      if (msg.task_id) await kvPut(env, 'resp:' + msg.task_id, body);
      return signed(body, secret);
    }
    return new Response('unknown type', { status: 400 });
  },
};
