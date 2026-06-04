const crypto = require('crypto');
const http = require('http'); // Or use fetch/axios in a real app
const { generateSignature } = require('./auth');

// Simulated client credentials
const CLIENT_ID = 'client_123abc';
const CLIENT_SECRET = 'super_secret_key_v1';
const HOST = 'localhost';
const PORT = 3000;
const PATH = '/api/v1/messages/send';

function sendWhatsAppMessage(customerPhone, message) {
  const method = 'POST';
  const timestamp = Date.now().toString();
  const nonce = crypto.randomBytes(16).toString('hex'); // 32 chars random string
  
  const bodyObj = {
    customer_phone: customerPhone,
    message: message
  };
  const bodyString = JSON.stringify(bodyObj);

  // Generate HMAC signature
  const signature = generateSignature(CLIENT_SECRET, method, PATH, CLIENT_ID, timestamp, nonce, bodyString);

  // Set up request options
  const options = {
    hostname: HOST,
    port: PORT,
    path: PATH,
    method: method,
    headers: {
      'Content-Type': 'application/json',
      'x-client-id': CLIENT_ID,
      'x-timestamp': timestamp,
      'x-nonce': nonce,
      'x-signature': signature,
      'Content-Length': Buffer.byteLength(bodyString)
    }
  };

  const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(`[Status Code]: ${res.statusCode}`);
      console.log(`[Response]: ${data}`);
    });
  });

  req.on('error', (e) => {
    console.error(`Problem with request: ${e.message}`);
  });

  // Write payload and finish request
  req.write(bodyString);
  req.end();
}

console.log('Sending authorized request...');
sendWhatsAppMessage('+19876543210', 'Hello from the secure client!');
