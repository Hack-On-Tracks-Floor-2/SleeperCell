# InsiderLens: Known Limitations & Threat Model Scope

## 1. What InsiderLens Detects
- **Encrypted Exfiltration:** Volume anomalies, upload-to-download asymmetry, new destination rarity, and off-hours data transfers.
- **Internal Staging:** Sudden anomalous bursts in internal file system reads prior to departure or notice windows.
- **DNS Tunnelling:** High entropy query labels and abnormally high unique subdomain rates.

## 2. Explicit Non-Goals & Limitations
1. **No Payload Decryption:** InsiderLens operates strictly on flow-level behavioral metadata (bytes, duration, ports, TLS handshake identifiers, SNI, packet counts). It does not perform SSL/TLS interception or deep payload inspection.
2. **Steganography & In-Protocol Covert Channels:** Sub-threshold volume changes hidden within sanctioned protocols (e.g. 50 KB image with hidden payload inside Slack) are below the statistical volume radar.
3. **Physical Exfiltration:** USB drives, camera snapshots of screens, or physical printouts are out of network scope.
4. **Offline Resilience:** The GenAI layer requires cached embeddings/responses or an active on-prem LLM server (Ollama / vLLM); deterministic fallback templates are provided for total network disconnection.
