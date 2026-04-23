# Web3 & DApp Security — Tactical Pillar

> **Context:** Decentralized Applications (DApps) shift much of the critical logic and state to the frontend and the blockchain payload. Traditional web backend vulnerabilities take a back seat to frontend cryptographic risks, signature malleability, and decentralized storage manipulation.

---

## 1. Hardcoded Private Keys & RPC Abuse
- **Scenario:** Developers embed keys in the frontend build process to interact with specific contracts, pay gas fees automatically, or use premium RPC nodes.
- **Tactic:** Webpack or Vite exposes the keys in the output bundles or source maps (`main.js.map`). Attackers extract Infura/Alchemy keys to drain quotas or extract `ethers.Wallet` private keys to drain funds.
- **`grep_search`:** `PRIVATE_KEY`, `mnemonic`, `0x`, `Infura`, `Alchemy`, `ethers.Wallet`, `process.env.NEXT_PUBLIC_PRIVATE_KEY`.

## 2. EIP-712 Signature Replay & Malleability
- **Scenario:** The application uses off-chain signatures for gasless transactions or authorization.
- **Tactic:** 
  - **Cross-Chain Replay:** If the signature payload lacks `chainID`, a signature meant for a Testnet or Polygon can be replayed on Ethereum Mainnet.
  - **Same-Chain Replay:** If the payload lacks a `nonce`, the attacker can submit the exact same signature multiple times (e.g., claiming a reward 10 times).
- **`grep_search`:** `signTypedData`, `_signTypedData`, `ecrecover`, `nonce:`, `chainId:`.

## 3. Insecure Client-Side Transaction Construction
- **Scenario:** The frontend calculates critical values (balances, slippage, payment amounts) and builds the raw transaction payload.
- **Tactic:** The attacker intercepts the transaction using a proxy or modified client before it hits MetaMask/WalletConnect. They alter the `data` payload or the `value` parameter, signing a transaction that benefits them (e.g., swapping the recipient address to their own).
- **Audit:** Never trust frontend-calculated values for `amountOutMinimum` or transaction destinations.

## 4. Decentralized Storage (IPFS/Arweave) Poisoning
- **Scenario:** DApps fetch NFT metadata or frontend assets via IPFS hashes (CIDs).
- **Tactic:** If the DApp allows users to upload content to IPFS and renders it without sanitization (e.g., SVG NFTs or HTML files), it creates an Unrestricted Stored XSS via IPFS gateway.
- **`grep_search`:** `ipfs://`, `gateway.pinata.cloud`, `dangerouslySetInnerHTML`.

## 5. RPC Node Hijacking & Eclipse Attacks
- **Scenario:** The application allows users to define custom RPC endpoints for network connectivity.
- **Tactic:** Attacker provides a malicious RPC node that performs eclipse attacks, returning forged block data, fake balances, or censoring transactions to force the user into making incorrect financial decisions.

## Strategic Checklist
1. [ ] Audit the build process (`.env.production`, Webpack) to ensure keys are not bundled.
2. [ ] Review EIP-712 structured data signing implementation for `domainSeparator`, `nonce`, and `chainID`.
3. [ ] Check for frontend-only state checks prior to transaction signing.
4. [ ] Validate how IPFS content is rendered on the UI (sanitize SVG/HTML).

---
*Tags: #web3 #dapp #smart-contract #private-key #eip712 #ipfs #shiva-vault*
