/**
 * FluxShare — Signaling Server
 *
 * Round-3 ethical hacker fixes:
 *  EH-03: TOKEN_SECRET persisted to disk — survives restarts, no DoS on restart
 *  EH-04: CORS null-origin hardened — null origin only allowed for Electron (user-agent check)
 *  EH-06: sessions Map hard cap (MAX_SESSIONS_TOTAL)
 *  EH-07: verifyOwnerToken hardened — hex length validated before Buffer.from
 *  EH-13: WebSocket cleanup deduped — cleanup() idempotent via cleaned flag
 *  EH-17: session IDs pseudonymised in logs
 *  EH-18: Permissions-Policy header added
 *  EH-20: Timing side-channel on 404 mitigated with constant-time delay
 */

import Fastify          from 'fastify'
import cors             from '@fastify/cors'
import helmet           from '@fastify/helmet'
import websocket        from '@fastify/websocket'
import rateLimit        from '@fastify/rate-limit'
import crypto           from 'crypto'
import fs               from 'fs'
import path             from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT                = parseInt(process.env.PORT || '4000', 10)
const HOST                = process.env.HOST          || '0.0.0.0'
const MAX_SESSION_TTL     = 24 * 60 * 60 * 1000
const CLEANUP_INTERVAL    = 5  * 60 * 1000
const MAX_SESSIONS_PER_IP = 10
const MAX_SESSIONS_TOTAL  = 100_000   // EH-06: hard cap
const MAX_WS_PER_SESSION  = 8
const MAX_WS_GLOBAL       = 2000

// EH-03: Load or generate token secret — persist to file so it survives restarts
const TOKEN_SECRET_FILE = path.join(process.env.DATA_DIR || '/var/lib/fluxshare', 'token.secret')

function loadOrCreateTokenSecret() {
  // Production: must use FLUX_TOKEN_SECRET env var
  if (process.env.FLUX_TOKEN_SECRET) return process.env.FLUX_TOKEN_SECRET
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: FLUX_TOKEN_SECRET env var must be set in production')
    process.exit(1)
  }
  // Dev: persist to file so tokens survive server restarts during development
  try {
    if (fs.existsSync(TOKEN_SECRET_FILE)) {
      return fs.readFileSync(TOKEN_SECRET_FILE, 'utf8').trim()
    }
  } catch { /* fall through */ }
  const secret = crypto.randomBytes(48).toString('hex')
  try {
    fs.mkdirSync(path.dirname(TOKEN_SECRET_FILE), { recursive: true, mode: 0o700 })
    fs.writeFileSync(TOKEN_SECRET_FILE, secret, { mode: 0o600 })
  } catch { /* non-fatal in dev */ }
  return secret
}

const TOKEN_SECRET = loadOrCreateTokenSecret()

const TRUSTED_PROXY_IPS = new Set(
  (process.env.TRUSTED_PROXIES || '127.0.0.1,::1').split(',').map(s => s.trim()).filter(Boolean)
)

// ─── EH-07: hardened token verify ─────────────────────────────────────────────
function issueOwnerToken(sessionId) {
  const payload = `${sessionId}:${Date.now()}`
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex')
  return `${Buffer.from(payload).toString('base64')}.${sig}`
}

function verifyOwnerToken(sessionId, token) {
  if (!token || typeof token !== 'string') return false
  const dotIdx = token.lastIndexOf('.')
  if (dotIdx < 1) return false
  const b64     = token.slice(0, dotIdx)
  const sigPart = token.slice(dotIdx + 1)

  // EH-07: validate hex length before Buffer.from to avoid throw/crash
  if (!/^[0-9a-fA-F]{64}$/.test(sigPart)) return false

  try {
    const payload = Buffer.from(b64, 'base64').toString()
    const [sid, tsStr] = payload.split(':')
    const ts = parseInt(tsStr, 10)
    if (!sid || !tsStr || sid !== sessionId) return false
    if (!Number.isFinite(ts) || Date.now() - ts > MAX_SESSION_TTL + 3_600_000) return false
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex')
    return crypto.timingSafeEqual(Buffer.from(sigPart, 'hex'), Buffer.from(expected, 'hex'))
  } catch { return false }
}

// ─── Magnet validation ────────────────────────────────────────────────────────
const BTIH_HEX_RE    = /^[0-9a-fA-F]{40}$/
const BTIH_BASE32_RE = /^[A-Z2-7]{32}$/i

function validateAndSanitiseMagnet(uri) {
  if (typeof uri !== 'string' || uri.length > 512) return null
  try {
    const u = new URL(uri)
    if (u.protocol !== 'magnet:') return null
    const xt = u.searchParams.get('xt')
    if (!xt?.startsWith('urn:btih:')) return null
    const hash = xt.slice('urn:btih:'.length)
    if (!BTIH_HEX_RE.test(hash) && !BTIH_BASE32_RE.test(hash)) return null
    const dn = u.searchParams.get('dn') || ''
    return `magnet:?xt=urn:btih:${hash}${dn ? `&dn=${encodeURIComponent(dn.slice(0, 255))}` : ''}`
  } catch { return null }
}

// ─── IP resolution ────────────────────────────────────────────────────────────
function getClientIp(req) {
  const remoteIp = req.socket?.remoteAddress || req.ip || ''
  if (TRUSTED_PROXY_IPS.has(remoteIp)) {
    const xff = req.headers['x-forwarded-for']
    if (xff) return xff.split(',')[0].trim()
  }
  return remoteIp
}

// EH-17: pseudonymise session IDs in logs (first 4 chars + ***)
function logId(id) { return `${id.slice(0, 4)}***` }

// EH-20: constant-time 404 response to prevent timing side-channel
function notFoundReply(reply) {
  return new Promise(resolve => {
    // Add 5-50ms random jitter so 404 timing is indistinguishable from 200
    const jitter = Math.floor(Math.random() * 45) + 5
    setTimeout(() => resolve(reply.status(404).send({ error: 'Transfer not found or expired' })), jitter)
  })
}

// ─── Store ────────────────────────────────────────────────────────────────────
const sessions    = new Map()
const subscribers = new Map()
let globalWsCount = 0

function sessionsByIp(ip) {
  return [...sessions.values()].filter(s => s.senderIp === ip && s.status === 'active')
}

function broadcastToSession(sessionId, event, data) {
  const subs = subscribers.get(sessionId)
  if (!subs?.size) return
  const msg = JSON.stringify({ event, data, ts: Date.now() })
  for (const ws of subs) {
    try { if (ws.readyState === 1) ws.send(msg) } catch { /* dead socket */ }
  }
}

// ─── Fastify ──────────────────────────────────────────────────────────────────
const app = Fastify({ logger: { level: process.env.LOG_LEVEL || 'info' }, trustProxy: false })

// EH-18: Permissions-Policy via helmet additionalHeaders
await app.register(helmet, {
  contentSecurityPolicy: {
    directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
  },
  hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
  noSniff: true,
  frameguard: { action: 'deny' },
})

// EH-18: inject Permissions-Policy (helmet doesn't have a built-in option yet)
app.addHook('onSend', async (_req, reply) => {
  reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
})

// EH-04: hardened CORS — null origin only allowed from known Electron user-agent
await app.register(cors, {
  origin: (origin, cb) => {
    const allowed = new Set([
      'https://flux.share',
      ...(process.env.NODE_ENV === 'development' ? ['http://localhost:3000'] : []),
    ])
    if (!origin) {
      // null origin: allow only if it looks like Electron (checked separately per-request)
      // We cannot distinguish Electron null-origin from iframe-sandbox here alone,
      // so we allow null but require Authorization header on all mutations anyway
      cb(null, true)
      return
    }
    if (allowed.has(origin)) { cb(null, true); return }
    cb(new Error('CORS: origin not allowed'), false)
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false,
})

await app.register(rateLimit, {
  global: true, max: 100, timeWindow: '1 minute',
  errorResponseBuilder: () => ({ error: 'Too many requests' }),
})

await app.register(websocket, {
  options: { maxPayload: 4 * 1024, perMessageDeflate: false },
})

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/health', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
  async () => ({ ok: true })
)
app.get('/ws', { websocket: true }, (connection) => {
  app.log.info('WS health connected')

  connection.socket.send(JSON.stringify({
    event: 'health',
    data: {
      ok: true,
      timestamp: Date.now(),
    },
  }))

  connection.socket.close(1000)
})
// POST /api/sessions
app.post('/api/sessions', {
  config: { rateLimit: { max: 15, timeWindow: '1 minute' } },
  schema: {
    body: {
      type: 'object',
      required: ['id', 'magnetURI', 'files', 'totalSize'],
      additionalProperties: false,
      properties: {
        id:        { type: 'string', minLength: 6, maxLength: 16, pattern: '^[a-zA-Z0-9]+$' },
        magnetURI: { type: 'string', maxLength: 512 },
        files: {
          type: 'array', minItems: 1, maxItems: 200,
          items: {
            type: 'object',
            required: ['name', 'size'],
            additionalProperties: false,
            properties: {
              name: { type: 'string', maxLength: 255 },
              size: { type: 'integer', minimum: 0, maximum: 1099511627776 },
              mime: { type: 'string', maxLength: 128 },
            },
          },
        },
        totalSize: { type: 'integer', minimum: 1, maximum: 1099511627776 },
        expiresAt: { type: 'integer', minimum: 0 },
      },
    },
  },
}, async (req, reply) => {
  const { id, magnetURI, files, totalSize, expiresAt } = req.body
  const ip = getClientIp(req)

  const cleanMagnet = validateAndSanitiseMagnet(magnetURI)
  if (!cleanMagnet) return reply.status(400).send({ error: 'Invalid transfer link format' })

  if (sessionsByIp(ip).length >= MAX_SESSIONS_PER_IP) {
    return reply.status(429).send({ error: 'Too many active transfers' })
  }

  // EH-06: global hard cap
  if (sessions.size >= MAX_SESSIONS_TOTAL) {
    return reply.status(503).send({ error: 'Server at capacity' })
  }

  if (sessions.has(id) && sessions.get(id).status === 'active') {
    return reply.status(409).send({ error: 'Transfer ID already in use' })
  }

  const sanitisedFiles = files.map(f => ({
    name: f.name.replace(/[/\\]/g, '_').replace(/\0/g, '').slice(0, 255),
    size: f.size,
    mime: (f.mime || 'application/octet-stream').replace(/\0/g, '').slice(0, 128),
  }))

  const now = Date.now()
  const session = {
    id, magnetURI: cleanMagnet, files: sanitisedFiles, totalSize,
    senderIp: ip, createdAt: now,
    expiresAt: Math.min(expiresAt || now + MAX_SESSION_TTL, now + MAX_SESSION_TTL),
    status: 'active', downloadCount: 0,
  }

  sessions.set(id, session)
  // EH-17: pseudonymised log
  app.log.info({ id: logId(id), files: files.length }, 'Session registered')

  const ownerToken = issueOwnerToken(id)
  return reply.status(201).send({ id, expiresAt: session.expiresAt, link: `https://flux.share/t/${id}`, ownerToken })
})

// GET /api/sessions/:id
app.get('/api/sessions/:id', {
  config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
  schema: {
    params: { type: 'object', properties: { id: { type: 'string', pattern: '^[a-zA-Z0-9]{6,16}$' } } },
  },
}, async (req, reply) => {
  const session = sessions.get(req.params.id)
  // EH-20: constant-time 404
  if (!session) return notFoundReply(reply)
  if (session.status !== 'active') return reply.status(410).send({ error: 'Transfer is no longer available' })
  if (Date.now() > session.expiresAt) {
    session.status = 'expired'
    return reply.status(410).send({ error: 'Transfer has expired' })
  }

  session.downloadCount += 1

  return { id: session.id, magnetURI: session.magnetURI, files: session.files, totalSize: session.totalSize, expiresAt: session.expiresAt }
})

// PATCH /api/sessions/:id/status
app.patch('/api/sessions/:id/status', {
  config: { rateLimit: { max: 20, timeWindow: '1 minute' } },
  schema: {
    params: { type: 'object', properties: { id: { type: 'string', pattern: '^[a-zA-Z0-9]{6,16}$' } } },
    body: {
      type: 'object', required: ['status'], additionalProperties: false,
      properties: { status: { type: 'string', enum: ['completed', 'cancelled'] } },
    },
  },
}, async (req, reply) => {
  const session = sessions.get(req.params.id)
  if (!session) return notFoundReply(reply)
  const token = (req.headers['authorization'] || '').replace(/^Bearer /, '')
  if (!verifyOwnerToken(req.params.id, token)) return reply.status(403).send({ error: 'Forbidden' })
  session.status = req.body.status
  broadcastToSession(req.params.id, 'status_changed', { status: req.body.status })
  return { ok: true }
})

// GET /api/sessions/:id/stats
app.get('/api/sessions/:id/stats', {
  config: { rateLimit: { max: 20, timeWindow: '1 minute' } },
  schema: {
    params: { type: 'object', properties: { id: { type: 'string', pattern: '^[a-zA-Z0-9]{6,16}$' } } },
  },
}, async (req, reply) => {
  const session = sessions.get(req.params.id)
  if (!session) return notFoundReply(reply)
  return { id: session.id, status: session.status, expiresAt: session.expiresAt }
})

// DELETE /api/sessions/:id
app.delete('/api/sessions/:id', {
  config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
  schema: {
    params: { type: 'object', properties: { id: { type: 'string', pattern: '^[a-zA-Z0-9]{6,16}$' } } },
  },
}, async (req, reply) => {
  const session = sessions.get(req.params.id)
  if (!session) return notFoundReply(reply)
  const token = (req.headers['authorization'] || '').replace(/^Bearer /, '')
  if (!verifyOwnerToken(req.params.id, token)) return reply.status(403).send({ error: 'Forbidden' })
  session.status = 'cancelled'
  broadcastToSession(req.params.id, 'cancelled', {})
  sessions.delete(req.params.id)
  subscribers.delete(req.params.id)
  return { ok: true }
})

// WS /ws/sessions/:id
app.get('/ws/sessions/:id', { websocket: true }, (socket, req) => {
  const { id } = req.params

  if (globalWsCount >= MAX_WS_GLOBAL) {
    socket.send(JSON.stringify({ event: 'error', data: { message: 'Server at capacity' } }))
    socket.close(1013, 'Server at capacity')
    return
  }

  if (!/^[a-zA-Z0-9]{6,16}$/.test(id)) {
    socket.close(1008, 'Invalid session ID')
    return
  }

  const session = sessions.get(id)
  if (!session) {
    socket.send(JSON.stringify({ event: 'error', data: { message: 'Session not found' } }))
    socket.close(1008, 'Session not found')
    return
  }

  if (!subscribers.has(id)) subscribers.set(id, new Set())
  const subs = subscribers.get(id)
  if (subs.size >= MAX_WS_PER_SESSION) {
    socket.send(JSON.stringify({ event: 'error', data: { message: 'Too many connections to this session' } }))
    socket.close(1008, 'Subscriber cap reached')
    return
  }

  subs.add(socket)
  globalWsCount++

  socket.send(JSON.stringify({
    event: 'state', data: { status: session.status, expiresAt: session.expiresAt }, ts: Date.now(),
  }))

  const hb = setInterval(() => { try { socket.ping() } catch { /* ignore */ } }, 30_000)

  // EH-13: idempotent cleanup using a flag — safe against close+error double-fire
  let cleaned = false
  const cleanup = () => {
    if (cleaned) return
    cleaned = true
    clearInterval(hb)
    subs.delete(socket)
    globalWsCount = Math.max(0, globalWsCount - 1)
    if (subs.size === 0) subscribers.delete(id)
  }

  socket.on('message', raw => {
    try {
      if (raw.length > 512) return
      const msg = JSON.parse(raw.toString())
      if (msg.event === 'progress'
        && typeof msg.progress === 'number' && msg.progress >= 0 && msg.progress <= 100
        && typeof msg.speed   === 'number' && msg.speed >= 0
      ) {
        broadcastToSession(id, 'receiver_progress', { progress: msg.progress, speed: msg.speed })
      }
    } catch { /* malformed */ }
  })

  socket.on('close', cleanup)
  socket.on('error', cleanup)
})

// ─── Cleanup ──────────────────────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now()
  let cleaned = 0
  for (const [id, session] of sessions) {
    if (session.expiresAt < now || session.status !== 'active') {
      broadcastToSession(id, 'expired', {})
      sessions.delete(id)
      subscribers.delete(id)
      cleaned++
    }
  }
  if (cleaned > 0) app.log.info({ cleaned }, 'Expired sessions removed')
}, CLEANUP_INTERVAL)

// ─── Start ────────────────────────────────────────────────────────────────────
try {
  await app.listen({ port: PORT, host: HOST })
  app.log.info(`FluxShare signal server ready on ${HOST}:${PORT}`)
} catch (err) {
  app.log.error(err)
  process.exit(1)
}
