# Web3 & DApp Security — Tactical Pillar

> **Context:** Decentralized Applications (DApps) shift much of the critical logic and state to the frontend and the blockchain payload. Traditional web backend vulnerabilities take a back seat to frontend cryptographic risks.

---

## 1. Hardcoded Private Keys & Mnemonic Phrases
- **Scenario:** Developers embed keys in the frontend build process to interact with specific contracts or pay gas fees automatically.
- **Tactic:** Webpack or Vite exposes the keys in the output bundles or source maps (`main.js.map`).
- **`grep_search`:** `PRIVATE_KEY`, `mnemonic`, `0x`, `Infura`, `Alchemy`, `ethers.Wallet`.

## 2. Insecure Client-Side Validation of Transaction Data
- **Scenario:** The frontend validates the balance or the amount to send, and builds the raw transaction payload.
- **Tactic:** The attacker intercepts the request before it hits MetaMask/WalletConnect and alters the `data` payload or the `value`, signing a completely different transaction than the one validated by the UI.

## 3. RPC Node Hijacking
- **Scenario:** The application allows users to define custom RPC endpoints for network connectivity.
- **Tactic:** Attacker provides a malicious RPC node that performs eclipse attacks, returning forged block data, fake balances, or censoring transactions.

## 4. Replay Attacks across Chains
- **Scenario:** A signature is requested for authorization on Ethereum Mainnet.
- **Tactic:** If the signature does not include `chainID` and a `nonce` (`EIP-712`), the attacker can replay that exact signature on Polygon or another EVM chain to drain funds or authorize actions.

## Strategic Checklist
1. [ ] Audit the build process (`.env.production`) to ensure keys are not bundled.
2. [ ] Review how EIP-712 structured data signing is implemented.
3. [ ] Check for frontend-only state checks prior to transaction signing.

---
*Tags: #web3 #dapp #smart-contract #private-key #shiva-vault*
