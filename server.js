/**
 * FluxShare — Signaling Server
 */

import Fastify from 'fastify'
import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import websocket from '@fastify/websocket'
import rateLimit from '@fastify/rate-limit'
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// ─────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '4000', 10)
const HOST = process.env.HOST || '0.0.0.0'

const MAX_SESSION_TTL = 24 * 60 * 60 * 1000
const CLEANUP_INTERVAL = 5 * 60 * 1000

const MAX_SESSIONS_PER_IP = 10
const MAX_SESSIONS_TOTAL = 100_000

const MAX_WS_PER_SESSION = 8
const MAX_WS_GLOBAL = 2000

// ─────────────────────────────────────────────────────────────
// Token secret
// ─────────────────────────────────────────────────────────────
const TOKEN_SECRET_FILE = path.join(
  process.env.DATA_DIR || '/var/lib/fluxshare',
  'token.secret'
)

function loadOrCreateTokenSecret() {
  if (process.env.FLUX_TOKEN_SECRET) {
    return process.env.FLUX_TOKEN_SECRET
  }

  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: FLUX_TOKEN_SECRET must be set')
    process.exit(1)
  }

  try {
    if (fs.existsSync(TOKEN_SECRET_FILE)) {
      return fs.readFileSync(TOKEN_SECRET_FILE, 'utf8').trim()
    }
  } catch {}

  const secret = crypto.randomBytes(48).toString('hex')

  try {
    fs.mkdirSync(path.dirname(TOKEN_SECRET_FILE), {
      recursive: true,
      mode: 0o700,
    })

    fs.writeFileSync(TOKEN_SECRET_FILE, secret, {
      mode: 0o600,
    })
  } catch {}

  return secret
}

const TOKEN_SECRET = loadOrCreateTokenSecret()

// ─────────────────────────────────────────────────────────────
// Fastify
// ─────────────────────────────────────────────────────────────
const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
  },
  trustProxy: false,
})

// ─────────────────────────────────────────────────────────────
// Plugins
// ─────────────────────────────────────────────────────────────
await app.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  frameguard: {
    action: 'deny',
  },
})

app.addHook('onSend', async (_req, reply) => {
  reply.header(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()'
  )
})

await app.register(cors, {
  origin: (origin, cb) => {
    const allowed = new Set([
      'https://flux.share',
      ...(process.env.NODE_ENV === 'development'
        ? ['http://localhost:3000']
        : []),
    ])

    if (!origin) {
      cb(null, true)
      return
    }

    if (allowed.has(origin)) {
      cb(null, true)
      return
    }

    cb(new Error('CORS blocked'), false)
  },

  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
})

await app.register(rateLimit, {
  global: true,
  max: 100,
  timeWindow: '1 minute',
  errorResponseBuilder: () => ({
    error: 'Too many requests',
  }),
})

await app.register(websocket, {
  options: {
    maxPayload: 4 * 1024,
    perMessageDeflate: false,
  },
})

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────
const BTIH_HEX_RE = /^[0-9a-fA-F]{40}$/
const BTIH_BASE32_RE = /^[A-Z2-7]{32}$/i

function validateAndSanitiseMagnet(uri) {
  if (typeof uri !== 'string' || uri.length > 512) {
    return null
  }

  try {
    const u = new URL(uri)

    if (u.protocol !== 'magnet:') {
      return null
    }

    const xt = u.searchParams.get('xt')

    if (!xt?.startsWith('urn:btih:')) {
      return null
    }

    const hash = xt.slice('urn:btih:'.length)

    if (!BTIH_HEX_RE.test(hash) && !BTIH_BASE32_RE.test(hash)) {
      return null
    }

    return uri
  } catch {
    return null
  }
}

function issueOwnerToken(sessionId) {
  const payload = `${sessionId}:${Date.now()}`

  const sig = crypto
    .createHmac('sha256', TOKEN_SECRET)
    .update(payload)
    .digest('hex')

  return `${Buffer.from(payload).toString('base64')}.${sig}`
}

function verifyOwnerToken(sessionId, token) {
  if (!token || typeof token !== 'string') {
    return false
  }

  const dotIdx = token.lastIndexOf('.')

  if (dotIdx < 1) {
    return false
  }

  const b64 = token.slice(0, dotIdx)
  const sigPart = token.slice(dotIdx + 1)

  if (!/^[0-9a-fA-F]{64}$/.test(sigPart)) {
    return false
  }

  try {
    const payload = Buffer.from(b64, 'base64').toString()

    const [sid, tsStr] = payload.split(':')

    const ts = parseInt(tsStr, 10)

    if (!sid || sid !== sessionId) {
      return false
    }

    if (!Number.isFinite(ts)) {
      return false
    }

    if (Date.now() - ts > MAX_SESSION_TTL + 3600000) {
      return false
    }

    const expected = crypto
      .createHmac('sha256', TOKEN_SECRET)
      .update(payload)
      .digest('hex')

    return crypto.timingSafeEqual(
      Buffer.from(sigPart, 'hex'),
      Buffer.from(expected, 'hex')
    )
  } catch {
    return false
  }
}

// ─────────────────────────────────────────────────────────────
// Store
// ─────────────────────────────────────────────────────────────
const sessions = new Map()
const subscribers = new Map()

let globalWsCount = 0

function broadcastToSession(sessionId, event, data) {
  const subs = subscribers.get(sessionId)

  if (!subs?.size) {
    return
  }

  const msg = JSON.stringify({
    event,
    data,
    ts: Date.now(),
  })

  for (const ws of subs) {
    try {
      if (ws.readyState === 1) {
        ws.send(msg)
      }
    } catch {}
  }
}

// ─────────────────────────────────────────────────────────────
// Health routes
// ─────────────────────────────────────────────────────────────
app.get('/health', async () => {
  return {
    ok: true,
    uptime: process.uptime(),
    timestamp: Date.now(),
  }
})

app.get('/ws', { websocket: true }, (connection) => {
  const socket = connection.socket

  app.log.info('WS health connected')

  socket.send(
    JSON.stringify({
      event: 'health',
      data: {
        ok: true,
        timestamp: Date.now(),
      },
    })
  )

  
  // IMPORTANT:
  // delay close so Render proxy finishes upgrade properly
  setTimeout(() => {
    try {
      socket.close()
    } catch {}
  }, 1000)
})

// ─────────────────────────────────────────────────────────────
// Create session
// ─────────────────────────────────────────────────────────────
app.post('/api/sessions', async (req, reply) => {
  const {
    id,
    magnetURI,
    files,
    totalSize,
    expiresAt,
  } = req.body

  if (!validateAndSanitiseMagnet(magnetURI)) {
    return reply.status(400).send({
      error: 'Invalid magnet URI',
    })
  }

  if (sessions.size >= MAX_SESSIONS_TOTAL) {
    return reply.status(503).send({
      error: 'Server at capacity',
    })
  }

  if (sessions.has(id)) {
    return reply.status(409).send({
      error: 'Session already exists',
    })
  }

  const now = Date.now()

  const session = {
    id,
    magnetURI,
    files,
    totalSize,
    createdAt: now,
    expiresAt: Math.min(
      expiresAt || now + MAX_SESSION_TTL,
      now + MAX_SESSION_TTL
    ),
    status: 'active',
  }

  sessions.set(id, session)

  const ownerToken = issueOwnerToken(id)

  app.log.info(`Session created ${id}`)

  return reply.status(201).send({
    id,
    expiresAt: session.expiresAt,
    ownerToken,
  })
})

// ─────────────────────────────────────────────────────────────
// Get session
// ─────────────────────────────────────────────────────────────
app.get('/api/sessions/:id', async (req, reply) => {
  const session = sessions.get(req.params.id)

  if (!session) {
    return reply.status(404).send({
      error: 'Transfer not found',
    })
  }

  return session
})

// ─────────────────────────────────────────────────────────────
// Delete session
// ─────────────────────────────────────────────────────────────
app.delete('/api/sessions/:id', async (req, reply) => {
  const token = (req.headers.authorization || '')
    .replace(/^Bearer /, '')

  if (!verifyOwnerToken(req.params.id, token)) {
    return reply.status(403).send({
      error: 'Forbidden',
    })
  }

  sessions.delete(req.params.id)
  subscribers.delete(req.params.id)

  return {
    ok: true,
  }
})

// ─────────────────────────────────────────────────────────────
// Session WebSocket
// ─────────────────────────────────────────────────────────────
app.get(
  '/ws/sessions/:id',
  { websocket: true },
  (connection, req) => {
    const socket = connection.socket

    const { id } = req.params

    app.log.info(`WS session connect ${id}`)

    if (globalWsCount >= MAX_WS_GLOBAL) {
      socket.send(JSON.stringify({
        event: 'error',
        data: {
          message: 'Server at capacity',
        },
      }))

      socket.close(1013)
      return
    }

    if (!/^[a-zA-Z0-9]{6,16}$/.test(id)) {
      socket.close(1008)
      return
    }

    const session = sessions.get(id)

    if (!session) {
      socket.send(JSON.stringify({
        event: 'error',
        data: {
          message: 'Session not found',
        },
      }))

      socket.close(1008)
      return
    }

    if (!subscribers.has(id)) {
      subscribers.set(id, new Set())
    }

    const subs = subscribers.get(id)

    if (subs.size >= MAX_WS_PER_SESSION) {
      socket.send(JSON.stringify({
        event: 'error',
        data: {
          message: 'Too many connections',
        },
      }))

      socket.close(1008)
      return
    }

    subs.add(socket)

    globalWsCount++

    socket.send(JSON.stringify({
      event: 'state',
      data: {
        status: session.status,
        expiresAt: session.expiresAt,
      },
      ts: Date.now(),
    }))

    const heartbeat = setInterval(() => {
      try {
        socket.ping()
      } catch {}
    }, 30000)

    let cleaned = false

    const cleanup = () => {
      if (cleaned) {
        return
      }

      cleaned = true

      clearInterval(heartbeat)

      subs.delete(socket)

      globalWsCount = Math.max(
        0,
        globalWsCount - 1
      )

      if (subs.size === 0) {
        subscribers.delete(id)
      }

      app.log.info(`WS disconnected ${id}`)
    }

    socket.on('message', raw => {
      try {
        if (raw.length > 512) {
          return
        }

        const msg = JSON.parse(raw.toString())

        if (
          msg.event === 'progress' &&
          typeof msg.progress === 'number' &&
          typeof msg.speed === 'number'
        ) {
          broadcastToSession(id, 'receiver_progress', {
            progress: msg.progress,
            speed: msg.speed,
          })
        }
      } catch {}
    })

    socket.on('close', cleanup)
    socket.on('error', cleanup)
  }
)

// ─────────────────────────────────────────────────────────────
// Cleanup
// ─────────────────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now()

  let cleaned = 0

  for (const [id, session] of sessions) {
    if (
      session.expiresAt < now ||
      session.status !== 'active'
    ) {
      broadcastToSession(id, 'expired', {})

      sessions.delete(id)
      subscribers.delete(id)

      cleaned++
    }
  }

  if (cleaned > 0) {
    app.log.info(`Cleaned ${cleaned} sessions`)
  }
}, CLEANUP_INTERVAL)

// ─────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────
try {
  await app.listen({
    port: PORT,
    host: HOST,
  })

  app.log.info(
    `FluxShare signaling server running on ${HOST}:${PORT}`
  )
} catch (err) {
  app.log.error(err)
  process.exit(1)
}
