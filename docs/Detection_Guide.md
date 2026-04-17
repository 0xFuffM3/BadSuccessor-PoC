# 🕵️ Detection Guide for BadSuccessor

This document provides defenders with actionable queries, Event IDs, and SIEM rules to detect exploitation of the BadSuccessor vulnerability.

## 📊 Log Sources Required

- **Active Directory** – Security Event Logs (Domain Controllers)
- **Advanced Audit Policy** – Must enable:
  - `Audit Directory Service Access` (subcategory: `Directory Service Changes`)
  - `Audit Kerberos Service Ticket Operations`
  - `Audit Account Management`

## 🔍 KQL Hunting Queries (Microsoft Sentinel / Defender)

Full queries are in [`detection/badsuccessor_hunting.kql`](../detection/badsuccessor_hunting.kql). Below are key patterns:

### 1. Suspicious dMSA Creation

Look for new `msDS-GroupManagedServiceAccount` objects created by non‑privileged users.

### 2. Modification of Supersedence Attributes

Event ID **5136** (Directory Service Change) with:
- Attribute LDAP name: `msDS-ManagedAccountPrecededByLink` or `msDS-DelegatedMSAState`
- Caller is **not** a member of `Domain Admins`, `Enterprise Admins`, or `Account Operators`.

### 3. Kerberos TGS Request for dMSA with S4U2Self

Event ID **4769** (A Kerberos service ticket was requested) where:
- `TargetUserName` ends with `$` (dMSA or computer account)
- `TicketOptions` contains `0x40810000` (S4U2Self flag)
- `ServiceName` is the dMSA account itself

Combine with **4768** (TGT request) to trace back to the requesting computer.

## 🛠️ Sigma Rules (for Splunk, Elastic, etc.)

```yaml
title: BadSuccessor dMSA Supersedence Modification
id: 9a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects modification of msDS-ManagedAccountPrecededByLink
logsource:
    product: windows
    service: security
    definition: 'Advanced Audit Policy: Directory Service Changes'
detection:
    selection:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-ManagedAccountPrecededByLink'
    filter:
        - CallerUserSid: 'S-1-5-21-*-512'   # Domain Admins
        - CallerUserSid: 'S-1-5-21-*-519'   # Enterprise Admins
    condition: selection and not filter
falsepositives: Rare; legitimate supersedence only by domain admins.
level: high