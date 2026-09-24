const express = require('express')
const { verifyReceipt } = require('@at1c/sdk')
const { paymentMiddleware, x402ResourceServer } = require('@x402-avm/express')
const { HTTPFacilitatorClient } = require('@x402-avm/core/server')
const { registerExactAvmScheme } = require('@x402-avm/avm/exact/server')
const { ALGORAND_MAINNET_CAIP2 } = require('@x402-avm/avm')

const app = express()
app.use(express.json())
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});
const PAY_TO = 'IUCQ6VSUINTBEATREWRWSCWV26THLJ44PRGIA7X4V626LQA4BHOE3ZDEQ4'

const facilitatorClient = new HTTPFacilitatorClient({
  url: 'https://facilitator.goplausible.xyz'
})

const resourceServer = new x402ResourceServer(facilitatorClient)
registerExactAvmScheme(resourceServer)

const routes = {
  'POST /v1/verify': {
    accepts: {
      scheme: 'exact',
      network: ALGORAND_MAINNET_CAIP2,
      asset: '31566704',
      payTo: PAY_TO,
      price: '$0.03',
      maxTimeoutSeconds: 300,
    },
    description: 'AT1C receipt verification — cryptographic proof that a human approved this AI agent action',
    extra: { tag: 'x402-global-challenge' },
    mimeType: 'application/json',
  }
}

app.use(paymentMiddleware(routes, resourceServer))

app.post('/v1/verify', (req, res) => {
  const receipt = req.body
  if (!receipt || !receipt.receiptId) {
    return res.status(400).json({ valid: false, reason: 'missing_receipt' })
  }
  try {
    const result = verifyReceipt(receipt)
    return res.status(200).json(result)
  } catch (err) {
    return res.status(400).json({ valid: false, reason: 'malformed_receipt' })
  }
})

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'AT1C Verify Endpoint' })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`AT1C verify endpoint running on port ${PORT}`)
})
