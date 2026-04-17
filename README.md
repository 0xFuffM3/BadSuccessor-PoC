# 🛡️ Advanced BadSuccessor (CVE-2025-53779) – Weaponized PoC & Detection Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell Gallery](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)

**A fully automated, production‑ready exploitation and detection suite for the BadSuccessor vulnerability in Windows Server 2025 Active Directory.**

> **⚠️ Important:** This tool is intended for **authorized security assessments, red team exercises, and educational purposes only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

---

## 📖 Executive Summary

The **BadSuccessor** vulnerability (internally tracked by Microsoft as CVE-2025-53779) allows a low‑privileged Active Directory user with **`CreateChild` permissions on any Organizational Unit (OU)** to impersonate **any user in the domain** – including Domain Admins. The flaw resides in the new **Delegated Managed Service Account (dMSA)** feature introduced in Windows Server 2025.

This repository provides:
- A **fully automated PowerShell script** (`Invoke-BadSuccessor.ps1`) that weaponizes the attack with pre‑flight checks, error handling, and Rubeus integration.
- **Defender‑friendly resources**: KQL hunting queries, Event ID analysis, and a hardening guide.
- **In‑depth technical documentation** explaining the KDC, PAC, and attribute manipulation.

---

## 🔬 Technical Breakdown (Simplified)

1. **dMSA Background** – dMSAs are a new account type in Windows Server 2025 that support supersedence: a new dMSA can replace an old one via the `msDS-ManagedAccountPrecededByLink` attribute.
2. **The Flaw** – The KDC blindly trusts this attribute. When a dMSA is configured with a superseded account (e.g., `CN=Administrator,CN=Users,...`), the KDC includes the **PAC (Privilege Attribute Certificate)** of the superseded account in tickets issued to the dMSA.
3. **Attack Path** – An attacker with `CreateChild` rights on an OU:
   - Creates a computer account.
   - Creates a dMSA and grants the computer account permission to retrieve its password.
   - Sets the dMSA’s `msDS-ManagedAccountPrecededByLink` to the DN of a high‑value target (e.g., Domain Admin).
   - Uses the computer account to request a TGT, then a TGS for the dMSA with S4U2Self – obtaining a service ticket impersonating the target.
   - Injects the ticket → **full impersonation**.

---

## 🎯 Attack Prerequisites

- **Domain Controller** running **Windows Server 2025** (any build).
- **KDS Root Key** generated (automatic when first dMSA is created).
- **Low‑privileged AD account** with `CreateChild` permission on **any OU** (by default, `Authenticated Users` have this on the `Computers` OU!).
- **PowerShell 5.1+** with the `ActiveDirectory` module (RSAT).
- **Rubeus.exe** (latest version) in the same directory as the script or in `%PATH%`.

---

## 🚀 Quick Start (Offensive)

1. **Clone the repository**
   ```powershell
   git clone https://github.com/yourusername/Advanced-BadSuccessor.git
   cd Advanced-BadSuccessor
