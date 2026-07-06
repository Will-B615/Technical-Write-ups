# Entra ID Sign-in Logs: Cybersecurity Technical Write-Up 

  

## Purpose 

This write-up explains how Microsoft Entra ID sign-in logs support investigation of suspicious authentication activity, especially brute-force, password spray, and compromised-account scenarios. It is designed to help an analyst understand what the logs show, which fields matter most, and how to turn raw authentication telemetry into practical investigative decisions. 

  

## Executive overview 

Entra ID sign-in logs are one of the most valuable identity telemetry sources because they record each authentication attempt along with user, application, IP, device, location, result, and policy context. For an analyst, the key advantage is that the same log stream can reveal both the attack pattern, such as repeated failures, and the consequence, such as a later successful login from the same source. These logs become even more useful when interpreted alongside MFA, Conditional Access, and identity risk concepts from Entra’s broader identity protection stack. 

  

## Technical context 

Cloud identities are high-value targets because a valid sign-in can give an attacker immediate access to Microsoft 365, Azure-connected apps, and other tenant resources without needing traditional endpoint compromise first. Entra ID acts as the authentication and authorization layer for users, devices, apps, and services, so its sign-in records often become the first place to validate whether a suspicious alert reflects real account abuse. 

  

From an attack-chain perspective, sign-in logs are most useful during initial access, credential access validation, and defense evasion analysis. A pattern of many failures followed by one success may indicate password spraying, brute force, or the successful use of stolen credentials, while repeated MFA-related failures may indicate an attacker who has the password but is blocked by a second factor. Conditional Access and Identity Protection add additional context by showing whether the sign-in was allowed, blocked, or challenged based on location, device, risk, or required grant controls such as MFA. 

  

## Technical detail 

A sign-in log records who attempted access, which app they targeted, where the request came from, whether the sign-in was interactive, and the authentication result. Key fields shown in the lab include `userPrincipalName`, `appDisplayName`, `ipAddress`, `clientAppUsed`, `createdDateTime`, `conditionalAccessStatus`, `status.errorCode`, location details, and `appliedConditionalAccessPolicies`. Together, these fields let an analyst reconstruct both the event and the security controls that shaped its outcome. 

  

The `status.errorCode` field is especially important because it tells the analyst whether the attempt succeeded and, if it failed, why. In the example data, error code `0` means the sign-in succeeded. Other highlighted codes include `50126` for invalid username or password, `50053` for account lockout due to repeated failures, `50074` for MFA required but not completed, and `50055` for expired password. These values help distinguish a simple mistyped password from a blocked credential attack or an account that may be partially compromised but still protected by MFA. 

  

The lab also shows how to query this data in Splunk using the `azure:aad:signin` sourcetype. A broad query for all events establishes baseline activity, while filtering on `status.errorCode!=0` surfaces failed authentications for aggregation by user, source IP, and application. Grouping failures by `userPrincipalName` and collecting `ipAddress`, `appDisplayName`, and error codes helps identify accounts under attack and whether a single source is testing many identities or repeatedly targeting one user. 

  

A follow-on query that filters successful sign-ins from the suspicious IP address helps determine whether the attacker eventually gained access and to which applications. This is where sign-in logs shift from detection to confirmation: if the same IP that generated many failed attempts later produces `status.errorCode=0`, the analyst has a strong lead for compromise validation. The application field also matters because access to `OfficeHome` or other Microsoft 365 resources may indicate immediate exposure to email, files, collaboration tools, or downstream tokens. 

  

## Indicators and observables 

Important observables in Entra ID sign-in investigations include: 

  

- High counts of failed authentications for a single account or many accounts from one IP. 

- A transition from repeated failures to a successful sign-in from the same source. 

- Error code patterns such as `50126`, `50053`, `50074`, and `50055`. 

- Repeated targeting of the same application, such as `OfficeHome`. 

- Suspicious geography or unexpected `location` values for a known user. 

- Conditional Access results showing whether a policy was successful, blocked, or not applied. 

- MFA outcomes showing whether a user was prompted, satisfied the challenge, or failed to complete it. 

  

## Blind spots and limitations 

Sign-in logs are powerful, but they do not tell the whole story. They show authentication attempts and policy outcomes, not necessarily what the user did after access was granted, so analysts often need app activity logs, audit logs, endpoint telemetry, or mailbox investigation data to measure impact. They also depend on accurate enrichment, such as IP geolocation and policy logging, which can be imperfect or incomplete in some environments. 

  

A successful sign-in from an unusual IP is not automatically malicious. VPN use, roaming users, cloud proxies, security testing, and federated or hybrid identity behaviors can all create patterns that resemble attack traffic without representing compromise. 

  

## False positives and benign triggers 

Several legitimate scenarios can resemble suspicious authentication behavior: 

  

- A user repeatedly enters an outdated password after a recent change, generating multiple `50126` failures. 

- An account lockout (`50053`) triggered by a stale mobile client or cached credentials rather than active attack activity. 

- MFA prompts not completed (`50074`) because the user ignored or missed the notification. 

- Travel, remote work, or enterprise VPN use causing unfamiliar IP or location values. 

- Conditional Access marked `notApplied` due to policy scope, exclusion, or application mismatch rather than control failure. 

  

## Response actions 

When suspicious sign-in activity is detected, a structured response should include: 

  

1. Confirm the pattern by reviewing all failed and successful sign-ins for the affected user and source IP. 

2. Determine whether MFA was required, completed, bypassed, or failed, and review applied Conditional Access policies. 

3. Validate whether the user and location make business sense; if not, treat the activity as potential compromise. 

4. If compromise is likely, revoke sessions, reset the password, and require stronger authentication methods such as Authenticator, Windows Hello for Business, or FIDO2. 

5. Review downstream exposure by checking accessed applications, group membership, privileged roles, and related audit activity. 

6. Strengthen prevention by using MFA, Conditional Access, password protection, and risk-based policies to reduce the chance of future credential abuse. 

  

## Analyst takeaway 

The practical value of Entra ID sign-in logs is that they connect identity telemetry to attacker behavior in a way that is immediately actionable. For a Security or IAM analyst, the goal is not just to read the log, but to interpret whether the event reflects failed access, blocked compromise, or successful account takeover, then pivot quickly into containment and hardening actions. 
