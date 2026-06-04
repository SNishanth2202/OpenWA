const crypto = require('crypto');

/**
 * Validates the HMAC signature of an incoming request.
 * 
 * @param {string} clientSecret - The client's active secret key.
 * @param {string} method - HTTP method (e.g., 'POST').
 * @param {string} path - URL path (e.g., '/api/v1/messages/send').
 * @param {string} clientId - The x-client-id header.
 * @param {string} timestamp - The x-timestamp header.
 * @param {string} nonce - The x-nonce header.
 * @param {string} body - The raw request body as a string.
 * @param {string} providedSignature - The x-signature header from the request.
 * @returns {boolean} - True if signature is valid.
 */
function validateSignature(clientSecret, method, path, clientId, timestamp, nonce, body, providedSignature) {
  const payloadToSign = `${method.toUpperCase()}\n${path}\nx-client-id:${clientId}\nx-timestamp:${timestamp}\nx-nonce:${nonce}\n${body}`;
  
  const expectedSignature = crypto
    .createHmac('sha256', clientSecret)
    .update(payloadToSign)
    .digest('hex');

  // Use crypto.timingSafeEqual to prevent timing attacks
  if (expectedSignature.length !== providedSignature.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature),
    Buffer.from(providedSignature)
  );
}

/**
 * Generates an HMAC signature for a client request.
 * 
 * @param {string} clientSecret - The client's active secret key.
 * @param {string} method - HTTP method.
 * @param {string} path - URL path.
 * @param {string} clientId - The client ID.
 * @param {string} timestamp - The timestamp.
 * @param {string} nonce - The nonce.
 * @param {string} body - The request body string.
 * @returns {string} - The hex-encoded SHA256 HMAC signature.
 */
function generateSignature(clientSecret, method, path, clientId, timestamp, nonce, body) {
  const payloadToSign = `${method.toUpperCase()}\n${path}\nx-client-id:${clientId}\nx-timestamp:${timestamp}\nx-nonce:${nonce}\n${body}`;
  return crypto
    .createHmac('sha256', clientSecret)
    .update(payloadToSign)
    .digest('hex');
}

module.exports = {
  validateSignature,
  generateSignature
};
