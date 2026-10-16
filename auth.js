const crypto = require('node:crypto');
const db = require('./db.js');

// -----------------------------------------------------------------------------
// Rate Limiting & Brute-Force Protection
// -----------------------------------------------------------------------------
const loginAttempts = new Map(); // ip -> { count: number, lockUntil: number, lastAttempt: number }

function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) return { allowed: true };

  if (record.lockUntil > now) {
    const remainingSeconds = Math.ceil((record.lockUntil - now) / 1000);
    return {
      allowed: false,
      message: `Too many failed login attempts. Locked for security. Try again in ${remainingSeconds}s.`,
      remainingSeconds
    };
  }

  // Clear stale attempt counter if more than 15 minutes have passed
  if (now - record.lastAttempt > 15 * 60 * 1000) {
    loginAttempts.delete(ip);
    return { allowed: true };
  }

  return { allowed: true };
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, lockUntil: 0, lastAttempt: now };
  record.count += 1;
  record.lastAttempt = now;

  // Lock out after 5 failed attempts for 15 minutes
  if (record.count >= 5) {
    record.lockUntil = now + 15 * 60 * 1000;
  }

  loginAttempts.set(ip, record);
}

function resetFailedAttempts(ip) {
  loginAttempts.delete(ip);
}

// -----------------------------------------------------------------------------
// Cryptographic Password Hashing & Verification
// -----------------------------------------------------------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return {
    hash: derivedKey.toString('hex'),
    salt
  };
}

function verifyPassword(password, salt, storedHash) {
  try {
    const candidateKey = crypto.scryptSync(password, salt, 64);
    const storedBuffer = Buffer.from(storedHash, 'hex');
    if (candidateKey.length !== storedBuffer.length) return false;
    return crypto.timingSafeEqual(candidateKey, storedBuffer);
  } catch (err) {
    return false;
  }
}

// -----------------------------------------------------------------------------
// Session Management
// -----------------------------------------------------------------------------
// Session Management (Stateless HMAC-SHA256 for Robust Persistence)
// -----------------------------------------------------------------------------
const SESSION_TTL_DAYS = 30;

function getAuthSecret() {
  const owner = db.getOwner();
  return 'toji_jwt_key_' + (owner ? (owner.password_salt || owner.password_hash || 'owner_secret') : 'default_secret');
}

function createSessionToken(userId, ip = '', userAgent = '') {
  const expiresAtMs = Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;
  const expiresAt = new Date(expiresAtMs).toISOString();
  const owner = db.getOwner();
  const username = owner ? owner.username : 'Owner';

  const payloadObj = {
    uid: userId,
    usr: username,
    exp: expiresAtMs
  };
  const payloadStr = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const signature = crypto.createHmac('sha256', getAuthSecret()).update(payloadStr).digest('base64url');
  const token = `${payloadStr}.${signature}`;

  try {
    db.createSession(token, userId, expiresAt, ip, userAgent);
  } catch (e) {}

  return { token, expiresAt };
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadStr, signature] = parts;
  if (!payloadStr || !signature) return null;

  try {
    const expectedSig = crypto.createHmac('sha256', getAuthSecret()).update(payloadStr).digest('base64url');
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;

    const payload = JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Date.now()) return null;

    return {
      userId: payload.uid,
      username: payload.usr,
      expiresAt: new Date(payload.exp).toISOString()
    };
  } catch (err) {
    return null;
  }
}

function parseCookies(req) {
  const list = {};
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return list;

  cookieHeader.split(';').forEach(cookie => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    list[name] = decodeURIComponent(value);
  });

  return list;
}

function extractToken(req) {
  // 1. Check Bearer authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }

  // 2. Check toji_session cookie
  const cookies = parseCookies(req);
  if (cookies.toji_session) {
    return cookies.toji_session;
  }

  return null;
}

// -----------------------------------------------------------------------------
// Auth Service API
// -----------------------------------------------------------------------------
const authApi = {
  getAuthStatus(req) {
    const userCount = db.getUserCount();
    if (userCount === 0) {
      return { isSetup: false, isAuthenticated: false };
    }

    const token = extractToken(req);
    if (!token) {
      return { isSetup: true, isAuthenticated: false };
    }

    // 1. Verify stateless HMAC token
    const verified = verifySessionToken(token);
    if (verified) {
      return {
        isSetup: true,
        isAuthenticated: true,
        username: verified.username,
        userId: verified.userId
      };
    }

    // 2. Fallback to stateful session
    const session = db.getSession(token);
    if (session) {
      db.touchSession(token);
      return {
        isSetup: true,
        isAuthenticated: true,
        username: session.username,
        userId: session.user_id
      };
    }

    return { isSetup: true, isAuthenticated: false };
  },

  async setupOwner(username, password, ip = '') {
    if (db.getUserCount() > 0) {
      return { error: 'Master owner account has already been set up.', status: 403 };
    }

    if (!username || username.trim().length < 2) {
      return { error: 'Username must be at least 2 characters long.', status: 400 };
    }

    if (!password || password.length < 6) {
      return { error: 'Master password must be at least 6 characters long.', status: 400 };
    }

    const { hash, salt } = hashPassword(password);
    const user = db.createOwner(username.trim(), hash, salt);
    const session = createSessionToken(user.id, ip);

    return {
      success: true,
      username: user.username,
      token: session.token,
      expiresAt: session.expiresAt
    };
  },

  async login(password, ip = '', userAgent = '') {
    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
      return { error: rateCheck.message, status: 429 };
    }

    const owner = db.getOwner();
    if (!owner) {
      return { error: 'Application has not been set up yet.', status: 400 };
    }

    // Add 100ms deliberate delay to deter brute-force timing
    await new Promise(r => setTimeout(r, 100));

    const isValid = verifyPassword(password, owner.password_salt, owner.password_hash);
    if (!isValid) {
      recordFailedAttempt(ip);
      return { error: 'Invalid master password.', status: 401 };
    }

    resetFailedAttempts(ip);
    db.cleanupExpiredSessions();
    db.updateLastLogin(owner.id);

    const session = createSessionToken(owner.id, ip, userAgent);
    return {
      success: true,
      username: owner.username,
      token: session.token,
      expiresAt: session.expiresAt
    };
  },

  logout(req) {
    const token = extractToken(req);
    if (token) {
      db.deleteSession(token);
    }
    return { success: true };
  },

  changePassword(userId, currentPassword, newPassword) {
    const owner = db.getOwner();
    if (!owner || owner.id !== userId) {
      return { error: 'Owner account not found.', status: 404 };
    }

    if (!verifyPassword(currentPassword, owner.password_salt, owner.password_hash)) {
      return { error: 'Current master password is incorrect.', status: 400 };
    }

    if (!newPassword || newPassword.length < 6) {
      return { error: 'New password must be at least 6 characters.', status: 400 };
    }

    const { hash, salt } = hashPassword(newPassword);
    db.updateOwnerPassword(userId, hash, salt);

    // Revoke all existing sessions
    db.deleteUserSessions(userId);

    const session = createSessionToken(userId);
    return { success: true, token: session.token };
  },

  // Auth Middleware
  requireAuth(req, res) {
    const status = this.getAuthStatus(req);
    if (!status.isAuthenticated) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized. Master login required.', code: 'AUTH_REQUIRED' }));
      return null;
    }
    return status;
  }
};

module.exports = authApi;
