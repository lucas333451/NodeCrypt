import { generateClientId, encryptMessage, decryptMessage, logEvent, isString, isObject, getTime } from './utils.js';

// ---- Auth + persistence helpers (Cloudflare D1 + MailChannels) ----
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
const CODE_TTL = 10 * 60 * 1000; // 10 minutes
const CODE_RESEND_WINDOW = 60 * 1000; // 1 minute
const MAX_CODE_ATTEMPTS = 5;

const jsonResponse = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

const toHex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
const textToUint8 = (text) => new TextEncoder().encode(text);
const randomHex = (bytes = 16) => toHex(crypto.getRandomValues(new Uint8Array(bytes)));

const sha256Hex = async (text) => {
  const hash = await crypto.subtle.digest('SHA-256', textToUint8(text));
  return toHex(hash);
};

const pbkdf2Hash = async (password, salt) => {
  const keyMaterial = await crypto.subtle.importKey('raw', textToUint8(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: textToUint8(salt), iterations: 120000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return toHex(derived);
};

const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

async function sendEmailCode(env, email, code) {
  const fromEmail = env.MAIL_FROM || 'no-reply@yourdomain.com';
  const subject = 'Your NodeCrypt verification code';
  const text = `Your verification code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore it.`;
  await fetch('https://api.mailchannels.net/tx/v1/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      personalizations: [{ to: [{ email }] }],
      from: { email: fromEmail, name: 'NodeCrypt' },
      subject,
      content: [{ type: 'text/plain', value: text }],
    }),
  });
}

async function authenticateSession(env, token) {
  if (!token || !env.DB) return null;
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const row = await env.DB.prepare(
    `SELECT users.id as userId, users.username, users.email, sessions.expires_at as expiresAt
     FROM sessions JOIN users ON sessions.user_id = users.id
     WHERE sessions.token_hash = ? LIMIT 1`
  )
    .bind(tokenHash)
    .first();
  if (!row) return null;
  if (row.expiresAt < now) return null;
  return { userId: row.userId, username: row.username, email: row.email };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // WebSocket upgrade
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader === 'websocket') {
      const id = env.CHAT_ROOM.idFromName('chat-room');
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // API endpoints
    if (url.pathname.startsWith('/api/')) {
      try {
        // send email code
        if (url.pathname === '/api/auth/send-code' && request.method === 'POST') {
          const body = await request.json();
          const email = (body.email || '').trim().toLowerCase();
          if (!validateEmail(email)) return jsonResponse({ error: 'invalid_email' }, 400);
          if (!env.DB) return jsonResponse({ error: 'db_unavailable' }, 500);
          const now = Date.now();
          const recent = await env.DB.prepare(
            'SELECT created_at FROM email_codes WHERE email = ? ORDER BY id DESC LIMIT 1'
          )
            .bind(email)
            .first();
          if (recent && now - recent.created_at < CODE_RESEND_WINDOW) {
            return jsonResponse({ error: 'too_many_requests' }, 429);
          }
          const code = '' + Math.floor(100000 + Math.random() * 900000);
          const codeHash = await sha256Hex(code + email);
          await env.DB.prepare(
            'INSERT INTO email_codes (email, code_hash, expires_at, created_at, attempts) VALUES (?, ?, ?, ?, 0)'
          )
            .bind(email, codeHash, now + CODE_TTL, now)
            .run();
          await sendEmailCode(env, email, code);
          return jsonResponse({ ok: true });
        }

        // register
        if (url.pathname === '/api/auth/register' && request.method === 'POST') {
          const body = await request.json();
          const username = (body.username || '').trim();
          const email = (body.email || '').trim().toLowerCase();
          const password = body.password || '';
          const code = (body.code || '').trim();
          if (!env.DB) return jsonResponse({ error: 'db_unavailable' }, 500);
          if (!username || !password || !validateEmail(email) || code.length === 0) {
            return jsonResponse({ error: 'invalid_input' }, 400);
          }
          const now = Date.now();
          const codeRow = await env.DB.prepare(
            'SELECT * FROM email_codes WHERE email = ? ORDER BY id DESC LIMIT 1'
          )
            .bind(email)
            .first();
          if (!codeRow || codeRow.expires_at < now) {
            return jsonResponse({ error: 'code_expired' }, 400);
          }
          const codeHash = await sha256Hex(code + email);
          if (codeRow.code_hash !== codeHash) {
            await env.DB.prepare('UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?').bind(codeRow.id).run();
            if (codeRow.attempts + 1 >= MAX_CODE_ATTEMPTS) {
              await env.DB.prepare('DELETE FROM email_codes WHERE id = ?').bind(codeRow.id).run();
            }
            return jsonResponse({ error: 'code_invalid' }, 400);
          }
          await env.DB.prepare('DELETE FROM email_codes WHERE id = ?').bind(codeRow.id).run();

          const existing = await env.DB.prepare(
            'SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1'
          )
            .bind(username, email)
            .first();
          if (existing) return jsonResponse({ error: 'user_exists' }, 400);

          const userId = 'u_' + randomHex(12);
          const salt = randomHex(12);
          const pwHash = await pbkdf2Hash(password, salt);
          await env.DB.prepare(
            'INSERT INTO users (id, username, email, pw_hash, salt, created_at) VALUES (?, ?, ?, ?, ?, ?)'
          )
            .bind(userId, username, email, pwHash, salt, now)
            .run();

          const token = randomHex(32);
          const tokenHash = await sha256Hex(token);
          await env.DB.prepare(
            'INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
          )
            .bind('s_' + randomHex(10), userId, tokenHash, now + SESSION_TTL, now)
            .run();

          return jsonResponse({ ok: true, token, userId, username, expiresAt: now + SESSION_TTL });
        }

        // login
        if (url.pathname === '/api/auth/login' && request.method === 'POST') {
          const body = await request.json();
          const identifier = (body.identifier || '').trim();
          const password = body.password || '';
          if (!env.DB) return jsonResponse({ error: 'db_unavailable' }, 500);
          if (!identifier || !password) return jsonResponse({ error: 'invalid_input' }, 400);
          const userRow = await env.DB.prepare(
            'SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1'
          )
            .bind(identifier, identifier)
            .first();
          if (!userRow) return jsonResponse({ error: 'user_not_found' }, 404);
          const pwHash = await pbkdf2Hash(password, userRow.salt);
          if (pwHash !== userRow.pw_hash) return jsonResponse({ error: 'invalid_credentials' }, 401);
          const now = Date.now();
          const token = randomHex(32);
          const tokenHash = await sha256Hex(token);
          await env.DB.prepare(
            'INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
          )
            .bind('s_' + randomHex(10), userRow.id, tokenHash, now + SESSION_TTL, now)
            .run();
          return jsonResponse({
            ok: true,
            token,
            userId: userRow.id,
            username: userRow.username,
            expiresAt: now + SESSION_TTL,
          });
        }

        // history
        if (url.pathname === '/api/history' && request.method === 'GET') {
          if (!env.DB) return jsonResponse({ error: 'db_unavailable' }, 500);
          const authHeader = request.headers.get('Authorization') || '';
          const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
          const session = await authenticateSession(env, token);
          if (!session) return jsonResponse({ error: 'unauthorized' }, 401);

          const dialogId = url.searchParams.get('dialog');
          const afterId = url.searchParams.get('after');
          const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
          if (!dialogId) return jsonResponse({ error: 'invalid_dialog' }, 400);
          let query =
            'SELECT id, dialog_id, sender_id, ts, cipher, mime, client_meta FROM messages WHERE dialog_id = ?';
          const params = [dialogId];
          if (afterId) {
            query += ' AND id > ?';
            params.push(Number(afterId));
          }
          query += ' ORDER BY id ASC LIMIT ?';
          params.push(limit);
          const { results } = await env.DB.prepare(query).bind(...params).all();
          return jsonResponse({ ok: true, items: results || [] });
        }

        return jsonResponse({ error: 'not_found' }, 404);
      } catch (error) {
        logEvent('api-error', error, 'error');
        return jsonResponse({ error: 'internal_error' }, 500);
      }
    }

    // static assets
    return env.ASSETS.fetch(request);
  },
};

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.clients = {};
    this.channels = {};
    this.config = {
      seenTimeout: 60000,
      debug: false,
    };
    this.initRSAKeyPair();
  }

  async initRSAKeyPair() {
    try {
      let stored = await this.state.storage.get('rsaKeyPair');
      if (!stored) {
        const keyPair = await crypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
          },
          true,
          ['sign', 'verify']
        );

        const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([
          crypto.subtle.exportKey('spki', keyPair.publicKey),
          crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
        ]);

        stored = {
          rsaPublic: btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer))),
          rsaPrivateData: Array.from(new Uint8Array(privateKeyBuffer)),
          createdAt: Date.now(),
        };

        await this.state.storage.put('rsaKeyPair', stored);
      }

      if (stored.rsaPrivateData) {
        const privateKeyBuffer = new Uint8Array(stored.rsaPrivateData);
        stored.rsaPrivate = await crypto.subtle.importKey(
          'pkcs8',
          privateKeyBuffer,
          {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
          },
          false,
          ['sign']
        );
      }
      this.keyPair = stored;

      if (stored.createdAt && Date.now() - stored.createdAt > 24 * 60 * 60 * 1000) {
        if (Object.keys(this.clients).length === 0) {
          await this.state.storage.delete('rsaKeyPair');
          this.keyPair = null;
          await this.initRSAKeyPair();
        } else {
          await this.state.storage.put('pendingKeyRotation', true);
        }
      }
    } catch (error) {
      console.error('Error initializing RSA key pair:', error);
      throw error;
    }
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    if (!this.keyPair) {
      await this.initRSAKeyPair();
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    this.handleSession(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async handleSession(connection) {
    connection.accept();
    await this.cleanupOldConnections();

    const clientId = generateClientId();
    if (!clientId || this.clients[clientId]) {
      this.closeConnection(connection);
      return;
    }

    logEvent('connection', clientId, 'debug');
    this.clients[clientId] = {
      connection,
      seen: getTime(),
      key: null,
      shared: null,
      channel: null,
      userId: null,
    };

    try {
      this.sendMessage(
        connection,
        JSON.stringify({
          type: 'server-key',
          key: this.keyPair.rsaPublic,
        })
      );
    } catch (error) {
      logEvent('sending-public-key', error, 'error');
    }

    connection.addEventListener('message', async (event) => {
      const message = event.data;
      if (!isString(message) || !this.clients[clientId]) return;
      this.clients[clientId].seen = getTime();

      if (message === 'ping') {
        this.sendMessage(connection, 'pong');
        return;
      }

      if (!this.clients[clientId].shared && message.length < 2048) {
        try {
          const keys = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-384' },
            true,
            ['deriveBits', 'deriveKey']
          );
          const publicKeyBuffer = await crypto.subtle.exportKey('raw', keys.publicKey);
          const signature = await crypto.subtle.sign(
            { name: 'RSASSA-PKCS1-v1_5' },
            this.keyPair.rsaPrivate,
            publicKeyBuffer
          );
          const clientPublicKeyHex = message;
          const clientPublicKeyBytes = new Uint8Array(
            clientPublicKeyHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
          );
          const clientPublicKey = await crypto.subtle.importKey(
            'raw',
            clientPublicKeyBytes,
            { name: 'ECDH', namedCurve: 'P-384' },
            false,
            []
          );
          const sharedSecretBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: clientPublicKey },
            keys.privateKey,
            384
          );
          this.clients[clientId].shared = new Uint8Array(sharedSecretBits).slice(8, 40);

          const response =
            Array.from(new Uint8Array(publicKeyBuffer))
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('') +
            '|' +
            btoa(String.fromCharCode(...new Uint8Array(signature)));
          this.sendMessage(connection, response);
        } catch (error) {
          logEvent('message-key', [clientId, error], 'error');
          this.closeConnection(connection);
        }
        return;
      }

      if (this.clients[clientId].shared && message.length <= 8 * 1024 * 1024) {
        this.processEncryptedMessage(clientId, message);
      }
    });

    connection.addEventListener('close', async (event) => {
      const channel = this.clients[clientId].channel;
      if (channel && this.channels[channel]) {
        this.channels[channel].splice(this.channels[channel].indexOf(clientId), 1);
        if (this.channels[channel].length === 0) {
          delete this.channels[channel];
        } else {
          try {
            const members = this.channels[channel];
            for (const member of members) {
              const client = this.clients[member];
              if (this.isClientInChannel(client, channel)) {
                this.sendMessage(
                  client.connection,
                  encryptMessage(
                    {
                      a: 'l',
                      p: members.filter((value) => value !== member),
                    },
                    client.shared
                  )
                );
              }
            }
          } catch (error) {
            logEvent('close-list', [clientId, error], 'error');
          }
        }
      }
      if (this.clients[clientId]) {
        delete this.clients[clientId];
      }
    });
  }

  processEncryptedMessage(clientId, message) {
    let decrypted = null;
    try {
      decrypted = decryptMessage(message, this.clients[clientId].shared);
      if (!isObject(decrypted) || !isString(decrypted.a)) return;
      const action = decrypted.a;
      if (action === 'auth') {
        this.handleAuth(clientId, decrypted);
      } else if (action === 'j') {
        this.handleJoinChannel(clientId, decrypted);
      } else if (action === 'c') {
        this.handleClientMessage(clientId, decrypted);
      } else if (action === 'w') {
        this.handleChannelMessage(clientId, decrypted);
      }
    } catch (error) {
      logEvent('process-encrypted-message', [clientId, error], 'error');
    } finally {
      decrypted = null;
    }
  }

  async handleAuth(clientId, decrypted) {
    if (!isString(decrypted.p)) return;
    try {
      const session = await authenticateSession(this.env, decrypted.p);
      if (session) {
        this.clients[clientId].userId = session.userId;
      }
    } catch (err) {
      logEvent('auth', err, 'error');
    }
  }

  handleJoinChannel(clientId, decrypted) {
    if (!isString(decrypted.p) || this.clients[clientId].channel) return;
    if (!this.clients[clientId].userId) {
      this.closeConnection(this.clients[clientId].connection);
      return;
    }
    try {
      const channel = decrypted.p;
      this.clients[clientId].channel = channel;
      if (!this.channels[channel]) this.channels[channel] = [clientId];
      else this.channels[channel].push(clientId);
      this.broadcastMemberList(channel);
    } catch (error) {
      logEvent('message-join', [clientId, error], 'error');
    }
  }

  async handleClientMessage(clientId, decrypted) {
    if (!isString(decrypted.p) || !isString(decrypted.c) || !this.clients[clientId].channel) return;
    try {
      const channel = this.clients[clientId].channel;
      const targetClient = this.clients[decrypted.c];
      if (this.isClientInChannel(targetClient, channel)) {
        const messageObj = { a: 'c', p: decrypted.p, c: clientId };
        const encrypted = encryptMessage(messageObj, targetClient.shared);
        this.sendMessage(targetClient.connection, encrypted);
        messageObj.p = null;
      }
      await this.persistMessage(channel, this.clients[clientId].userId, decrypted.h, {
        mode: 'private',
        target: decrypted.c,
      });
    } catch (error) {
      logEvent('message-client', [clientId, error], 'error');
    }
  }

  async handleChannelMessage(clientId, decrypted) {
    if (!isObject(decrypted.p) || !this.clients[clientId].channel) return;
    try {
      const channel = this.clients[clientId].channel;
      const validMembers = Object.keys(decrypted.p).filter((member) => {
        const targetClient = this.clients[member];
        return isString(decrypted.p[member]) && this.isClientInChannel(targetClient, channel);
      });

      for (const member of validMembers) {
        const targetClient = this.clients[member];
        const messageObj = { a: 'c', p: decrypted.p[member], c: clientId };
        const encrypted = encryptMessage(messageObj, targetClient.shared);
        this.sendMessage(targetClient.connection, encrypted);
        messageObj.p = null;
      }

      await this.persistMessage(channel, this.clients[clientId].userId, decrypted.h, { mode: 'channel' });
    } catch (error) {
      logEvent('message-channel', [clientId, error], 'error');
    }
  }

  async persistMessage(dialogId, senderId, archiveCipher, meta = {}, ts = getTime()) {
    try {
      if (!archiveCipher || !this.env || !this.env.DB) return;
      await this.env.DB.prepare(
        'INSERT INTO messages (dialog_id, sender_id, ts, cipher, mime, client_meta) VALUES (?, ?, ?, ?, ?, ?)'
      )
        .bind(dialogId, senderId || 'anonymous', ts, archiveCipher, null, JSON.stringify(meta || {}))
        .run();
    } catch (err) {
      logEvent('persistMessage', err, 'error');
    }
  }

  broadcastMemberList(channel) {
    try {
      const members = this.channels[channel];
      for (const member of members) {
        const client = this.clients[member];
        if (this.isClientInChannel(client, channel)) {
          const messageObj = {
            a: 'l',
            p: members.filter((value) => value !== member),
          };
          const encrypted = encryptMessage(messageObj, client.shared);
          this.sendMessage(client.connection, encrypted);
          messageObj.p = null;
        }
      }
    } catch (error) {
      logEvent('broadcast-member-list', error, 'error');
    }
  }

  isClientInChannel(client, channel) {
    return client && client.connection && client.shared && client.channel && client.channel === channel;
  }

  sendMessage(connection, message) {
    try {
      if (connection.readyState === 1) {
        connection.send(message);
      }
    } catch (error) {
      logEvent('sendMessage', error, 'error');
    }
  }

  closeConnection(connection) {
    try {
      connection.close();
    } catch (error) {
      logEvent('closeConnection', error, 'error');
    }
  }

  async cleanupOldConnections() {
    const seenThreshold = getTime() - this.config.seenTimeout;
    const clientsToRemove = [];
    for (const clientId in this.clients) {
      if (this.clients[clientId].seen < seenThreshold) {
        clientsToRemove.push(clientId);
      }
    }
    for (const clientId of clientsToRemove) {
      try {
        this.clients[clientId].connection.close();
        delete this.clients[clientId];
      } catch (error) {
        logEvent('connection-seen', error, 'error');
      }
    }

    if (Object.keys(this.clients).length === 0 && Object.keys(this.channels).length === 0) {
      const pendingRotation = await this.state.storage.get('pendingKeyRotation');
      if (pendingRotation) {
        await this.state.storage.delete('rsaKeyPair');
        await this.state.storage.delete('pendingKeyRotation');
        this.keyPair = null;
        await this.initRSAKeyPair();
      }
    }
    return clientsToRemove.length;
  }
}
