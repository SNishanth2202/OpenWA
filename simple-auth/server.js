const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

// The static key (32-character string) generated for your use
const VALID_KEY = process.env.VALID_KEY || 'b63a9d74f28e1c5039a827bc4f1e5d9a'; // Replace with your actual key

// Middleware to verify the key
function verifyKey(req, res, next) {
    // The key should be passed in the 'x-api-key' header
    const clientKey = req.headers['x-api-key'];

    if (!clientKey) {
        return res.status(401).json({ success: false, error: 'Authentication required. Missing key.' });
    }

    if (clientKey !== VALID_KEY) {
        return res.status(403).json({ success: false, error: 'Invalid key.' });
    }

    // If the key is verified, proceed to send the message
    next();
}

app.use(express.json());

// Endpoint protected by the middleware
app.post('/api/messages/send', verifyKey, (req, res) => {
    const { customer_phone, message } = req.body;

    if (!customer_phone || !message) {
        return res.status(400).json({ success: false, error: 'Missing customer_phone or message' });
    }

    console.log(`[SUCCESS] Request verified. Sending message to ${customer_phone}: "${message}"`);
    
    // The backend logic to send the message via WhatsApp goes here
    
    res.json({
        success: true,
        message_status: 'sent',
        recipient: customer_phone
    });
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    console.log(`Your Secret Key is: ${VALID_KEY}`);
});
