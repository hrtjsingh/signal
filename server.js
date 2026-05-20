/**
 * FluxShare — Signaling Server
 * Fully fixed Fastify + WebSocket server
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

const MAX_SESSIONS_TOTAL = 100000
const MAX_WS_GLOBAL = 2000
const MAX_WS_PER_SESSION = 8

// ─────────────────────────────────────────────────────────────
// Token Secret
// ─────────────────────────────────────────────────────────────

const TOKEN_SECRET_FILE = path.join(
  process.env.DATA_DIR || './data',
  'token.secret'
)

function loadOrCreateTokenSecret() {
  if (process.env.FLUX_TOKEN_SECRET) {
    return process.env.FLUX_TOKEN_SECRET
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
    })

    fs.writeFileSync(TOKEN_SECRET_FILE, secret)
  } catch {}

  return secret
}

const TOKEN_SECRET = loadOrCreateTokenSecret()

// ─────────────────────────────────────────────────────────────
// Fastify
// ─────────────────────────────────────────────────────────────

const app = Fastify({
  logger: true,
})

// ─────────────────────────────────────────────────────────────
// Plugins
// ─────────────────────────────────────────────────────────────

await app.register(helmet, {
  contentSecurityPolicy: false,
})

await app.register(cors, {
  origin: true,
})

await app.register(rateLimit, {
  global: true,
  max: 100,
  timeWindow: '1 minute',
})

await app.register(websocket)

// ─────────────────────────────────────────────────────────────
// Store
// ─────────────────────────────────────────────────────────────

const sessions = new Map()
const subscribers = new Map()

let globalWsCount = 0

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

function broadcastToSession(sessionId, event, data) {
  const subs = subscribers.get(sessionId)

  if (!subs?.size) return

  const payload = JSON.stringify({
    event,
    data,
    ts: Date.now(),
  })

  for (const ws of subs) {
    try {
      if (ws.readyState === 1) {
        ws.send(payload)
      }
    } catch {}
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
  if (!token) return false

  const dot = token.lastIndexOf('.')

  if (dot < 0) return false

  const b64 = token.slice(0, dot)
  const sig = token.slice(dot + 1)

  try {
    const payload = Buffer.from(b64, 'base64').toString()

    const [sid] = payload.split(':')

    if (sid !== sessionId) {
      return false
    }

    const expected = crypto
      .createHmac('sha256', TOKEN_SECRET)
      .update(payload)
      .digest('hex')

    return crypto.timingSafeEqual(
      Buffer.from(sig),
      Buffer.from(expected)
    )
  } catch {
    return false
  }
}

// ─────────────────────────────────────────────────────────────
// Health Routes
// ─────────────────────────────────────────────────────────────

app.get('/health', async () => {
  return {
    ok: true,
    uptime: process.uptime(),
    timestamp: Date.now(),
  }
})

// IMPORTANT FIX
app.get('/ws', { websocket: true }, (connection, req) => {
  const socket = connection.socket

  app.log.info('WS health connected')

  socket.send(JSON.stringify({
    event: 'health',
    data: {
      ok: true,
      timestamp: Date.now(),
    },
  }))

  const heartbeat = setInterval(() => {
    try {
      socket.ping()
    } catch {}
  }, 30000)

  socket.on('close', () => {
    clearInterval(heartbeat)
    app.log.info('WS health disconnected')
  })

  socket.on('error', () => {
    clearInterval(heartbeat)
  })
})

// ─────────────────────────────────────────────────────────────
// Create Session
// ─────────────────────────────────────────────────────────────

app.post('/api/sessions', async (req, reply) => {
  const {
    id,
    magnetURI,
    files,
    totalSize,
  } = req.body

  if (!id || !magnetURI) {
    return reply.status(400).send({
      error: 'Missing fields',
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

  const session = {
    id,
    magnetURI,
    files,
    totalSize,
    status: 'active',
    createdAt: Date.now(),
    expiresAt: Date.now() + MAX_SESSION_TTL,
  }

  sessions.set(id, session)

  app.log.info(`Session created ${id}`)

  return reply.status(201).send({
    id,
    ownerToken: issueOwnerToken(id),
    expiresAt: session.expiresAt,
  })
})

// ─────────────────────────────────────────────────────────────
// Get Session
// ─────────────────────────────────────────────────────────────

app.get('/api/sessions/:id', async (req, reply) => {
  const session = sessions.get(req.params.id)

  if (!session) {
    return reply.status(404).send({
      error: 'Session not found',
    })
  }

  return session
})

// ─────────────────────────────────────────────────────────────
// Delete Session
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

    app.log.info(`WS connected ${id}`)

    if (globalWsCount >= MAX_WS_GLOBAL) {
      socket.close(1013)
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
    }))

    const heartbeat = setInterval(() => {
      try {
        socket.ping()
      } catch {}
    }, 30000)

    let cleaned = false

    const cleanup = () => {
      if (cleaned) return

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
        const msg = JSON.parse(raw.toString())

        if (
          msg.event === 'progress'
        ) {
          broadcastToSession(
            id,
            'receiver_progress',
            {
              progress: msg.progress,
              speed: msg.speed,
            }
          )
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

  for (const [id, session] of sessions) {
    if (session.expiresAt < now) {

      broadcastToSession(id, 'expired', {})

      sessions.delete(id)
      subscribers.delete(id)

      app.log.info(`Session expired ${id}`)
    }
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
    `FluxShare server running on ${HOST}:${PORT}`
  )
} catch (err) {
  app.log.error(err)
  process.exit(1)
}
