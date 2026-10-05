const express = require('express')
const { verifyReceipt } = require('@at1c/sdk')
const app = express()
app.set('trust proxy', true)
app.use(express.json())
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

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
