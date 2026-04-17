# 🔬 Technical Deep Dive: BadSuccessor (CVE-2025-53779)

## How the KDC is Tricked

The vulnerability lies in the Kerberos Key Distribution Center’s (KDC) handling of the **Delegated Managed Service Account (dMSA)** supersedence mechanism. Let’s break down the internals.

### dMSA Supersedence in Windows Server 2025

A dMSA is a special type of group Managed Service Account (gMSA) that supports:

- **`msDS-ManagedAccountPrecededByLink`** – A backlink attribute pointing to the dMSA that this account supersedes.
- **`msDS-DelegatedMSAState`** – An integer flag:
  - `1` = normal dMSA
  - `2` = superseding dMSA (i.e., this account replaces another)

When a dMSA has `msDS-DelegatedMSAState = 2` and `msDS-ManagedAccountPrecededByLink` set to the DN of another security principal (user, computer, or service account), the KDC **automatically includes the PAC of the superseded principal** in any service ticket issued to the dMSA.

### The PAC Inclusion Logic

During TGS-REQ processing, the KDC:

1. Receives a request for a service ticket for the dMSA (service = dMSA’s sAMAccountName).
2. Checks if the dMSA has `msDS-DelegatedMSAState = 2`.
3. Reads `msDS-ManagedAccountPrecededByLink`.
4. Retrieves the PAC of the referenced object (without verifying permissions or whether that object is even a dMSA!).
5. Constructs the final ticket with **the PAC of the superseded principal**, not the dMSA’s own PAC.

**Critical flaw:** There is **no access check** on the superseded principal. The KDC trusts the directory attribute unconditionally.

### Why Microsoft Won’t Patch It

Microsoft classifies this as a **feature misconfiguration** rather than a code vulnerability. The design assumption is that only administrators can set these attributes. However, in many Active Directory environments, low-privileged users have `CreateChild` permissions on OUs – which allows them to create a dMSA and, by default, **write all its attributes** (including `msDS-ManagedAccountPrecededByLink`).

Thus, the “fix” is to **tighten ACLs**, not to change the KDC.

### Attack Chain in Detail

1. **Create a computer account** – The attacker uses `New-ADComputer`. No special privileges needed if the user has `CreateChild` on the target OU.
2. **Create a dMSA** – Using `New-ADServiceAccount` with the `-Delegated` flag (Windows Server 2025 only). The attacker sets `-PrincipalsAllowedToRetrieveManagedPassword` to the computer account created in step 1.
3. **Set supersedence attributes** – Using `Set-ADObject` to modify `msDS-DelegatedMSAState = 2` and `msDS-ManagedAccountPrecededByLink = <DN of target user>`.
4. **Retrieve dMSA password hash** – The computer account (step 1) can request the dMSA’s blob from KDS and compute its AES256 key.
5. **Request TGT for computer account** – `Rubeus asktgt /user:PwnedPC$ /aes256:<key>`.
6. **Request TGS for dMSA with S4U2Self** – `Rubeus asktgs /service:dMSA$ /ticket:<TGT> /impersonateuser:Administrator /dmsa` (the `/dmsa` flag tells Rubeus to handle the special PAC inclusion).
7. **Inject ticket** – `Rubeus ptt /ticket:<TGS>`.
8. **Impersonate** – Now `klist` shows a ticket for `Administrator` to any service the dMSA is allowed to access.

### Key Takeaways for Red Teams

- This is a **lateral movement and privilege escalation** goldmine.
- The attack works against **any user** – not just domain admins.
- No elevated privileges required – just `CreateChild` on any OU (often granted to `Authenticated Users` on the default `Computers` OU).
- Can be used to **forge tickets for service accounts**, enabling further abuse (e.g., dumping LSA secrets).

### Mitigation from a Code Perspective

Microsoft could theoretically fix this by adding an ACL check: the principal setting `msDS-ManagedAccountPrecededByLink` must have `WriteProperty` on the target object. Until then, defenders must rely on **permission auditing** and **monitoring**.