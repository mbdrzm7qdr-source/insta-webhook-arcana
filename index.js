const express = require('express');
const { config } = require('dotenv');
const { genHmac, compareHmac } = require('./utils/crypto');
const crypto = require('node:crypto');
const app = express();

// Loads the environment variables
config();

app.use(express.urlencoded({ extended: false }));
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.get('/privacy', (req, res) => {
  res.send(`
    <html>
      <body>
        <h1>Privacy Policy</h1>
        <p>This application is a webhook integration with Meta/Instagram. 
        It receives and processes webhook events from Instagram.</p>
        <p>We do not store any personal data. All webhook data is processed 
        and discarded unless explicitly required for the application's function.</p>
        <p>If you have any questions, please contact us.</p>
      </body>
    </html>
  `);
});
/**
 * Handles the verification request meta sends to verify your webhook endpoint
 * Modify the API path and logic as you see fit.
 * The curent code logic handles the verification request perfectly well.
 * It verifies that the hub.verify_token value matches the verification token you provided when setting up the webhook on the App dashboard
 * If the verification token matches, it sends back the hub.challenge value
 */
app.get('/meta/webhook/verify_request', (req, res, next) => {
  try {
    const query = req.query;

    const hubVerifyToken = query['hub.verify_token'];
    const hubChallenge = query['hub.challenge'];

    if (hubVerifyToken !== process.env.META_HUB_VERIFY_TOKEN) {
      throw new Error("Verify token don't match");
    }

    res.status(200).send(hubChallenge);
  } catch (error) {
    next(error);
  }
});
app.get('/meta/webhook/instagram', (req, res, next) => {
  try {
    const query = req.query;
    const hubVerifyToken = query['hub.verify_token'];
    const hubChallenge = query['hub.challenge'];
    if (hubVerifyToken !== process.env.META_HUB_VERIFY_TOKEN) {
      throw new Error("Verify token don't match");
    }
    res.status(200).send(hubChallenge);
  } catch (error) {
    next(error);
  }
});
// Handle instagram webhook events
app.post('/meta/webhook/instagram', async (req, res, next) => {
  try {
    const x_hub_signature = req.headers['x-hub-signature-256'];

    if (!x_hub_signature) {
      throw new Error('x-hub-signature-256 header is missing');
    }

    // Generate a SHA256 signature using the payload and your app secret
    const localSig = crypto.createHmac('sha256', process.env.META_APP_SECRET).update(req.rawBody).digest('hex');

    // Compare the generated signature to the one in the x-hub-signature-256 header
    const metaSig = x_hub_signature.split('sha256=')[1];
    const sigMatched = compareHmac(metaSig, localSig);

    if (!sigMatched) {
      throw new Error("Signatures don't match");
    }

    const body = req.body;
const entry = body.entry?.[0];
const messaging = entry?.messaging?.[0];
const senderId = messaging?.sender?.id;
const messageText = messaging?.message?.text;

if (senderId && messageText) {
  const voiceflowResponse = await fetch('https://general-runtime.voiceflow.com/state/user/' + senderId + '/interact', {
    method: 'POST',
    headers: {
      'Authorization': process.env.VOICEFLOW_API_KEY,
      'Content-Type': 'application/json',
      'versionID': 'production'
    },
    body: JSON.stringify({
      action: {
        type: 'text',
        payload: messageText
      },
      projectID: '6992038979502f9204f0cc6a'
    })
  });

  const voiceflowData = await voiceflowResponse.json();
console.log('Voiceflow response:', JSON.stringify(voiceflowData));
const traces = Array.isArray(voiceflowData) ? voiceflowData : voiceflowData?.trace || [];
const replyText = traces
    .filter(trace => trace.type === 'text')
    .map(trace => trace.payload.message)
    .join(' ');

  if (replyText) {
    await fetch('https://graph.facebook.com/v18.0/me/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipient: { id: senderId },
        message: { text: replyText },
        access_token: process.env.META_PAGE_ACCESS_TOKEN
      })
    });
  }
}

} catch (error) {
    console.error('Webhook error:', error.message);
    next(error);
  }
});

// Central error handling middleware
app.use((err, req, res, next) => {
  let message = err.message !== undefined ? err.message : 'Internal server error';
  let status = err.code !== undefined ? err.code : 500;
  res.status(status).json({
    message,
    status,
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port:`, PORT);
});

module.exports = app;
