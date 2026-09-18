from algosdk import mnemonic, transaction
from algosdk.v2client import algod

# Connect to Algorand mainnet
client = algod.AlgodClient("", "https://mainnet-api.algonode.cloud", headers={"X-API-Key": ""})

# Your mnemonic — enter when prompted, never stored
mn = input("Enter your 25-word mnemonic: ")
private_key = mnemonic.to_private_key(mn)
from algosdk.account import address_from_private_key
address = address_from_private_key(private_key)

print(f"\nAddress: {address}")
confirm = input("Is this correct? (yes/no): ")
if confirm.lower() != "yes":
    print("Aborted.")
    exit()

# USDC asset ID on Algorand mainnet
USDC_ASSET_ID = 31566704

# Build opt-in transaction
params = client.suggested_params()
txn = transaction.AssetOptInTxn(address, params, USDC_ASSET_ID)
signed = txn.sign(private_key)
txid = client.send_transaction(signed)
print(f"\nOpt-in sent — transaction ID: {txid}")
print("Wait 5 seconds then check your balance.")
