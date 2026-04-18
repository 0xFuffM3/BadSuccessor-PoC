# SpecterOps Analysis: BadSuccessor Tradecraft

**Source:** SpecterOps Blog / Research Team

**Date:** April 2025

**Overview:**  
SpecterOps expanded on Akamai’s discovery, focusing on detection and real-world abuse potential. Their analysis highlights how the BadSuccessor vulnerability fits into existing Kerberos attack frameworks (e.g., Rubeus, Kekeo) and provides guidance for red teamers and defenders.

**Key Contributions:**
- **Rubeus Integration** – Added the `/dmsa` flag to `asktgs` to automatically handle dMSA supersedence ticket requests.
- **Detection Evasion** – Noted that modifying the supersedence attribute does not generate high-fidelity alerts unless advanced auditing is enabled.
- **Lateral Movement** – Using dMSA tickets, an attacker can pivot to any system where the impersonated user has access, without ever touching LSASS.

**Detection Recommendations (from SpecterOps):**
- Enable **Audit Directory Service Changes** (subcategory `DS Changes`) and monitor for changes to `msDS-ManagedAccountPrecededByLink`.
- Alert on **Event 4769** where `TicketOptions` includes `0x40810000` and the `TargetUserName` is a dMSA (ends with `$` but is not a computer).
- Harden OUs: remove `CreateChild` from non‑admins, especially on `CN=Computers`.

**Full Article:**  
[SpecterOps – BadSuccessor Deep Dive](https://specterops.io/blog/2025/10/20/the-near-return-of-the-king-account-takeover-using-the-badsuccessor-technique/)

**Relevant Tools:**  
- [Rubeus (GhostPack)](https://github.com/GhostPack/Rubeus) – v2.5.0+ includes `/dmsa`
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) – Can be extended to map `CreateChild` permissions on OUs.