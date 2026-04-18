# Akamai Original Research: BadSuccessor

**Title:** BadSuccessor: A New Active Directory Vulnerability Allowing Low-Privileged Users to Impersonate Anyone

**Author:** Yuval Gordon (Akamai Security Research)

**Publication Date:** March 2025

**Summary:**  
Akamai discovered that the new Delegated Managedhtt Service Account (dMSA) feature in Windows Server 2025 contains a logical flaw: the KDC does not validate the `msDS-ManagedAccountPrecededByLink` attribute. Any user with `CreateChild` permissions on an OU can create a dMSA, set the superseded account to a high-value target, and obtain a Kerberos ticket impersonating that target. Microsoft classified this as a design issue (won't fix) and recommends hardening OU permissions.

**Key Findings:**
- The default `Computers` OU grants `CreateChild` to `Authenticated Users`.
- Attack works against any user in the domain, including service accounts and domain admins.
- No patch is expected; mitigation is administrative.

**Original Blog Post:**  
[Akamai Blog – BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

**Recommended Reading:**  
- [Akamai’s Proof of Concept Script](https://github.com/akamai/BadSuccessor)
- [Microsoft Documentation on dMSA](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)