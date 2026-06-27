# M365 Legacy Auth & MFA Reporter

A white-hat Python security tool that scans Microsoft 365 users 
for legacy authentication exposure and weak MFA methods, generating 
a prioritised remediation report for security teams.

## What It Detects
- Users with no MFA enrolled
- Weak MFA methods (SMS, Voice Call, Basic Push)
- Legacy authentication protocols (IMAP, POP3, SMTP Auth, EAS)
- Admin accounts with insufficient authentication security

## Risk Scoring
| Level | Triggers |
|-------|----------|
| HIGH | Admin with any weakness OR 2+ indicators |
| MEDIUM | 1 risk indicator |
| LOW | Strong MFA, no legacy auth |

## MFA Method Classification
| Method | Rating |
|--------|--------|
| FIDO2 Security Key | ✅ Strong |
| Microsoft Authenticator (Number Matching) | ✅ Strong |
| Basic Push Notification | ⚠️ Weak |
| SMS | ⚠️ Weak |
| Voice Call | ⚠️ Weak |
| None | ❌ Critical |

## Tools Used
- Python 3.12
- Microsoft Graph API (architecture)
- HTML/CSS Dashboard

## Project Context
Built as part of AltSchool Africa Cybersecurity programme.
Covers: MFA Hardening, Legacy Auth Restriction, Identity Security.
