require('dotenv').config();
const express = require('express');
const Redis = require('ioredis');
const { validateSignature } = require('./auth');

const app = express();
const port = process.env.PORT || 3000;

// Connect to Redis (assuming local or configured via REDIS_URL)
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// --- Mock Database (In production, replace with PostgreSQL queries) ---
const MOCK_DB = {
  clients: {
    'client_123abc': {
      status: 'active',
      rateLimit: 60, // requests per minute
      activeSecrets: [
        'super_secret_key_v1', // Should be stored symmetrically encrypted in DB
        'super_secret_key_v2'  // To support key rotation seamlessly
      ]
    }
  }
};

// --- Middleware: Raw Body Parsing ---
// We need the raw body to verify the exact payload that was hashed by the client.
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

// --- Security Constants ---
const MAX_TIMESTAMP_AGE_MS = 5 * 60 * 1000; // 5 minutes

// --- Middleware: Authentication & Security ---
async function secureApi(req, res, next) {
  try {
    const clientId = req.headers['x-client-id'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    const signature = req.headers['x-signature'];

    // 1. Basic validation of required headers
    if (!clientId || !timestamp || !nonce || !signature) {
      return res.status(401).json({ success: false, error: 'Missing required security headers' });
    }

    // 2. Fetch Client Info
    const client = MOCK_DB.clients[clientId];
    if (!client || client.status !== 'active') {
      return res.status(401).json({ success: false, error: 'Invalid or inactive client' });
    }

    // 3. Timestamp Validation (Replay Attack Prevention)
    const requestTime = parseInt(timestamp, 10);
    const now = Date.now();
    if (isNaN(requestTime) || now - requestTime > MAX_TIMESTAMP_AGE_MS || requestTime > now + 60000) {
      // Reject if older than 5 mins or mysteriously in the future
      return res.status(401).json({ success: false, error: 'Timestamp expired or invalid' });
    }

    // 4. Nonce Validation (Replay Attack Prevention) using Redis
    // We store the nonce with a TTL slightly larger than our timestamp window
    const nonceKey = `nonce:${clientId}:${nonce}`;
    // SETNX sets the key only if it doesn't exist. Returns 1 if set, 0 if it exists.
    const isNewNonce = await redis.set(nonceKey, '1', 'NX', 'PX', MAX_TIMESTAMP_AGE_MS + 60000);
    
    if (isNewNonce === 0) {
      return res.status(401).json({ success: false, error: 'Nonce already used (Replay Attack)' });
    }

    // 5. Signature Validation (HMAC)
    let signatureValid = false;
    const body = req.rawBody || '';
    const path = req.originalUrl;
    const method = req.method;

    // Loop through active secrets (supports zero-downtime key rotation)
    for (const secret of client.activeSecrets) {
      if (validateSignature(secret, method, path, clientId, timestamp, nonce, body, signature)) {
        signatureValid = true;
        break;
      }
    }

    if (!signatureValid) {
      return res.status(401).json({ success: false, error: 'Invalid signature' });
    }

    // 6. Rate Limiting (Fixed Window per minute)
    const currentMinute = Math.floor(now / 60000);
    const rateLimitKey = `rate:${clientId}:${currentMinute}`;
    
    // Increment counter and set expiry if it's new
    const requestsThisMinute = await redis.incr(rateLimitKey);
    if (requestsThisMinute === 1) {
      await redis.expire(rateLimitKey, 60); // Expire after 60 seconds
    }

    if (requestsThisMinute > client.rateLimit) {
      return res.status(429).json({ success: false, error: 'Rate limit exceeded' });
    }

    // Attach client info to request for downstream handlers
    req.client = { id: clientId, ...client };
    next();
  } catch (err) {
    console.error('Auth Error:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
}

// --- Routes ---
app.post('/api/v1/messages/send', secureApi, (req, res) => {
  // At this point, the request is fully authenticated, rate-limited, and protected from replays.
  const { customer_phone, message } = req.body;

  if (!customer_phone || !message) {
    return res.status(400).json({ success: false, error: 'Missing customer_phone or message' });
  }

  console.log(`[x] Client ${req.client.id} sent message to ${customer_phone}: "${message}"`);
  
  // Here you would integrate with Meta's WhatsApp Cloud API or a provider like Twilio/MessageBird.
  
  res.json({
    success: true,
    message_id: `msg_${Date.now()}`,
    status: 'queued'
  });
});

app.listen(port, () => {
  console.log(`🚀 Secure WhatsApp API listening on port ${port}`);
});
