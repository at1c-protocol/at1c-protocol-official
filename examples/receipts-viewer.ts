const fs = require("fs")
const path = require("path")

// Lists receipts.json. This viewer only DISPLAYS receipts; it does not verify signatures.
// Verify with verifyReceiptV1 and your own pinned keys (see packages/sdk/README.md).
const receiptsFile = path.join(process.cwd(), "receipts.json")

function loadReceipts(): any[] {
  try {
    if (!fs.existsSync(receiptsFile)) {
      console.log("No receipts found yet.")
      return []
    }
    const parsed = JSON.parse(fs.readFileSync(receiptsFile, "utf-8"))
    return Array.isArray(parsed) ? parsed : []
  } catch (err) {
    console.error("Failed to load receipts:", err)
    return []
  }
}

function main() {
  const receipts = loadReceipts()

  console.log("\nAT1C Receipts")
  console.log("====================\n")

  if (receipts.length === 0) {
    console.log("No receipts recorded yet.")
    return
  }

  receipts.forEach((r: any, i: number) => {
    console.log(`Receipt #${i + 1}`)
    if (r.version === "1") {
      console.log(`ID: ${r.receipt_id}`)
      console.log(`Approver: ${r.approval?.authority}`)
      console.log(`Agent: ${r.actor?.agent_id}`)
      console.log(`Action: ${r.action?.type} (${r.action?.class}) on ${r.action?.resource}`)
      console.log(`Decision: ${r.decision}`)
      console.log(`Issued: ${r.issued_at}  Expires: ${r.expires_at}`)
    } else {
      console.log(`Legacy pre-v1 receipt (${r.receiptId ?? "no id"}): not verifiable under format 1.`)
    }
    console.log("----------------------")
  })
}

main()
