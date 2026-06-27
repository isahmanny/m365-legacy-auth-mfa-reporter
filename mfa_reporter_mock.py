"""
M365 Legacy Auth & MFA Method Reporter - Mock Data Version
===========================================================
Portfolio demonstration tool for AltSchool Africa Cybersecurity.
Simulates Microsoft 365 user authentication scanning, identifies
users on legacy authentication protocols and weak MFA methods,
and generates a prioritised HTML remediation report.

No Microsoft account or API credentials required.

Run:
    python mfa_reporter_mock.py
"""

import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# MOCK DATA — realistic M365 user auth profiles
# ─────────────────────────────────────────────

MOCK_USERS = [
    # ── HIGH RISK ──────────────────────────────────────────────
    {
        "id": "u001",
        "displayName": "Amina Yusuf",
        "email": "amina.yusuf@contoso.onmicrosoft.com",
        "department": "Finance",
        "jobTitle": "Finance Manager",
        "mfaEnabled": False,
        "mfaMethods": [],
        "legacyAuthProtocols": ["IMAP", "POP3", "SMTP Auth"],
        "lastSignIn": (datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accountEnabled": True,
        "isAdmin": False,
    },
    {
        "id": "u002",
        "displayName": "Chidi Okafor",
        "email": "chidi.okafor@contoso.onmicrosoft.com",
        "department": "IT",
        "jobTitle": "IT Administrator",
        "mfaEnabled": True,
        "mfaMethods": ["SMS"],
        "legacyAuthProtocols": ["SMTP Auth", "Exchange ActiveSync"],
        "lastSignIn": (datetime.datetime.utcnow() - datetime.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accountEnabled": True,
        "isAdmin": True,
    },
    {
        "id": "u003",
        "displayName": "Fatima Al-Hassan",
        "email": "fatima.alhassan@contoso.onmicrosoft.com",
        "department": "Executive",
        "jobTitle": "CEO",
        "mfaEnabled": True,
        "mfaMethods": ["Voice Call"],
        "legacyAuthProtocols": ["IMAP"],
        "lastSignIn": (datetime.datetime.utcnow() - datetime.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accountEnabled": True,
        "isAdmin": True,
    },

    # ── MEDIUM RISK ────────────────────────────────────────────
    {
        "id": "u004",
        "displayName": "James Okonkwo",
        "email": "james.okonkwo@contoso.onmicrosoft.com",
        "department": "Sales",
        "jobTitle": "Sales Lead",
        "mfaEnabled": True,
        "mfaMethods": ["SMS"],
        "legacyAuthProtocols": [],
        "lastSignIn": (datetime.datetime.utcnow() - datetime.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accountEnabled": True,
        "isAdmin": False,
    },
    {
        "id": "u005",
        "displayName": "Sarah Adeyemi",
        "email": "sarah.adeyemi@contoso.onmicrosoft.com",
        "department": "HR",
        "jobTitle": "HR Manager",
        "mfaEnabled": True,
        "mfaMethods": ["Basic Push"],
        "legacyAuthProtocols": ["POP3"],
        "lastSignIn": (datetime.datetime.utcnow() - datetime.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accountEnabled": True,
        "isAdmin": False,
    },

    # ── LOW RISK (secure) ──────────────────────────────────────
    {
        "id": "u006",
        "displayName": "Michael Eze",
        "email": "michael.eze@contoso.onmicrosoft.com",
        "department": "Engineering",
        "jobTitle": "Software Engineer",
        "mfaEnabled": True,
        "mfaMethods": ["Microsoft Authenticator (Number Matching)"],
        "legacyAuthProtocols": [],
        "lastSignIn": (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accountEnabled": True,
        "isAdmin": False,
    },
    {
        "id": "u007",
        "displayName": "Ngozi Ibrahim",
        "email": "ngozi.ibrahim@contoso.onmicrosoft.com",
        "department": "Engineering",
        "jobTitle": "DevOps Engineer",
        "mfaEnabled": True,
        "mfaMethods": ["FIDO2 Security Key"],
        "legacyAuthProtocols": [],
        "lastSignIn": (datetime.datetime.utcnow() - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accountEnabled": True,
        "isAdmin": True,
    },
    {
        "id": "u008",
        "displayName": "Ahmed Musa",
        "email": "ahmed.musa@contoso.onmicrosoft.com",
        "department": "Operations",
        "jobTitle": "Operations Manager",
        "mfaEnabled": True,
        "mfaMethods": ["Microsoft Authenticator (Number Matching)"],
        "legacyAuthProtocols": [],
        "lastSignIn": (datetime.datetime.utcnow() - datetime.timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accountEnabled": True,
        "isAdmin": False,
    },
]

# ─────────────────────────────────────────────
# RISK DEFINITIONS
# ─────────────────────────────────────────────
WEAK_MFA_METHODS  = {"sms", "voice call", "basic push", "phone"}
STRONG_MFA_METHODS = {"microsoft authenticator (number matching)", "fido2 security key",
                      "fido2", "windows hello", "certificate-based auth"}
LEGACY_PROTOCOLS  = {"imap", "pop3", "smtp auth", "exchange activesync",
                     "mapi over http", "rpc over http"}

REMEDIATION_MAP = {
    "No MFA enabled":
        "Immediately enrol user in Microsoft Authenticator with Number Matching.",
    "SMS MFA":
        "Upgrade to Microsoft Authenticator (Number Matching) — SMS is SIM-swappable.",
    "Voice Call MFA":
        "Upgrade to Microsoft Authenticator or FIDO2 — voice calls are interception-prone.",
    "Basic Push MFA":
        "Enable Number Matching on push notifications to prevent MFA fatigue attacks.",
    "IMAP":
        "Disable IMAP via Exchange Online Admin → disable legacy auth policy.",
    "POP3":
        "Disable POP3 via Exchange Online Admin → disable legacy auth policy.",
    "SMTP Auth":
        "Disable SMTP Auth unless required for line-of-business apps.",
    "Exchange ActiveSync":
        "Block EAS for non-compliant devices via Conditional Access policy.",
}


# ─────────────────────────────────────────────
# RISK ANALYSIS
# ─────────────────────────────────────────────
def assess_user(user: dict) -> tuple[str, list[str], list[str]]:
    reasons      = []
    remediations = []

    # No MFA at all
    if not user.get("mfaEnabled") or not user.get("mfaMethods"):
        reasons.append("MFA not enabled")
        remediations.append(REMEDIATION_MAP["No MFA enabled"])

    # Weak MFA methods
    for method in user.get("mfaMethods", []):
        if method.lower() in WEAK_MFA_METHODS:
            reasons.append(f"Weak MFA method: {method}")
            remediations.append(REMEDIATION_MAP.get(method, f"Upgrade from {method} to stronger method."))

    # Legacy auth protocols
    for proto in user.get("legacyAuthProtocols", []):
        reasons.append(f"Legacy auth enabled: {proto}")
        remediations.append(REMEDIATION_MAP.get(proto, f"Disable {proto} in Exchange Online."))

    # Admin with weak security — escalate risk
    is_admin = user.get("isAdmin", False)

    if not reasons:
        return "LOW", [], []

    if is_admin and len(reasons) >= 1:
        return "HIGH", reasons, remediations
    elif len(reasons) >= 2:
        return "HIGH", reasons, remediations
    else:
        return "MEDIUM", reasons, remediations


# ─────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────
def generate_report(users_with_risk: list[dict]) -> str:
    now    = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    high   = [u for u in users_with_risk if u["risk"] == "HIGH"]
    medium = [u for u in users_with_risk if u["risk"] == "MEDIUM"]
    low    = [u for u in users_with_risk if u["risk"] == "LOW"]

    def badge(risk):
        colors = {"HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#16a34a"}
        return f'<span class="badge" style="background:{colors[risk]}">{risk}</span>'

    def admin_tag(user):
        return '<span class="admin-tag">ADMIN</span>' if user.get("isAdmin") else ""

    def mfa_display(user):
        if not user.get("mfaEnabled") or not user.get("mfaMethods"):
            return '<span class="no-mfa">None</span>'
        methods = user.get("mfaMethods", [])
        out = []
        for m in methods:
            if m.lower() in WEAK_MFA_METHODS:
                out.append(f'<span class="weak-mfa">{m}</span>')
            else:
                out.append(f'<span class="strong-mfa">{m}</span>')
        return " ".join(out)

    def rows(lst):
        if not lst:
            return '<tr><td colspan="7" class="empty">No users in this category.</td></tr>'
        out = ""
        for item in lst:
            u = item["user"]
            legacy = ", ".join(u.get("legacyAuthProtocols", [])) or "—"
            remed  = "<br>".join([f"• {r}" for r in item["remediations"]]) if item["remediations"] else "—"
            out += f"""
            <tr>
              <td><strong>{u.get('displayName','—')}</strong> {admin_tag(u)}<br>
                  <small>{u.get('email','')}</small><br>
                  <small class="dept">{u.get('department','')} — {u.get('jobTitle','')}</small></td>
              <td>{mfa_display(u)}</td>
              <td class="mono legacy">{legacy}</td>
              <td>{badge(item['risk'])}</td>
              <td class="remed">{remed}</td>
            </tr>"""
        return out

    def section(title, emoji, lst):
        return f"""
        <section>
          <h2>{emoji} {title} <span class="count">({len(lst)})</span></h2>
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th>User</th><th>MFA Method</th><th>Legacy Auth</th>
                <th>Risk</th><th>Remediation Steps</th>
              </tr></thead>
              <tbody>{rows(lst)}</tbody>
            </table>
          </div>
        </section>"""

    no_mfa   = len([u for u in users_with_risk if not u["user"].get("mfaEnabled")])
    weak_mfa = len([u for u in users_with_risk
                    if u["user"].get("mfaMethods") and
                    any(m.lower() in WEAK_MFA_METHODS for m in u["user"].get("mfaMethods", []))])
    legacy   = len([u for u in users_with_risk if u["user"].get("legacyAuthProtocols")])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Legacy Auth & MFA Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Inter',sans-serif;background:#0a0f1e;color:#e2e8f0;min-height:100vh;padding:2rem 2.5rem}}

  header{{margin-bottom:2.5rem;padding-bottom:1.5rem;border-bottom:1px solid #1e293b}}
  .header-top{{display:flex;align-items:center;gap:1rem;margin-bottom:0.5rem}}
  .logo{{width:42px;height:42px;background:linear-gradient(135deg,#f59e0b,#ef4444);border-radius:10px;
         display:flex;align-items:center;justify-content:center;font-size:1.3rem}}
  header h1{{font-size:1.6rem;font-weight:700;color:#f1f5f9;letter-spacing:-0.02em}}
  .meta{{font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#475569}}
  .meta span{{margin-right:1.5rem}}
  .mock-badge{{display:inline-block;background:#1e3a5f;color:#60a5fa;border:1px solid #2563eb;
               padding:0.2rem 0.6rem;border-radius:4px;font-size:0.65rem;font-weight:600;
               letter-spacing:0.08em;margin-left:0.75rem;vertical-align:middle}}

  .stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:1rem;margin-bottom:2.5rem}}
  .card{{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:1.1rem 1.2rem}}
  .card .label{{font-size:0.68rem;color:#64748b;text-transform:uppercase;letter-spacing:0.1em;font-weight:600}}
  .card .val{{font-size:1.8rem;font-weight:700;margin-top:0.3rem;font-family:'JetBrains Mono',monospace}}
  .card.total  .val{{color:#818cf8}}
  .card.high   .val{{color:#f87171}}
  .card.medium .val{{color:#fbbf24}}
  .card.low    .val{{color:#4ade80}}
  .card.nomfa  .val{{color:#f87171}}
  .card.legacy .val{{color:#fb923c}}

  section{{margin-bottom:2.5rem}}
  section h2{{font-size:0.95rem;font-weight:600;color:#94a3b8;margin-bottom:0.75rem;
              display:flex;align-items:center;gap:0.4rem}}
  .count{{color:#475569;font-weight:400}}

  .table-wrap{{overflow-x:auto;border-radius:10px;border:1px solid #1e293b}}
  table{{width:100%;border-collapse:collapse;font-size:0.8rem}}
  thead th{{background:#0f172a;color:#475569;font-weight:600;text-transform:uppercase;
            letter-spacing:0.07em;font-size:0.68rem;padding:0.8rem 1rem;
            text-align:left;border-bottom:1px solid #1e293b}}
  tbody tr{{border-bottom:1px solid #0f172a;transition:background 0.12s}}
  tbody tr:hover{{background:#0f172a}}
  tbody tr:last-child{{border-bottom:none}}
  tbody td{{padding:0.75rem 1rem;color:#cbd5e1;vertical-align:top;line-height:1.6}}
  tbody td small{{color:#475569;font-size:0.7rem}}
  .dept{{color:#334155}}
  .mono{{font-family:'JetBrains Mono',monospace;font-size:0.75rem}}
  .legacy{{color:#fb923c}}
  .remed{{color:#94a3b8;font-size:0.78rem;line-height:1.8}}
  .empty{{text-align:center;color:#334155;padding:1.5rem!important}}

  .badge{{display:inline-block;padding:0.2rem 0.55rem;border-radius:4px;font-size:0.65rem;
          font-weight:700;letter-spacing:0.08em;color:#fff;font-family:'JetBrains Mono',monospace}}
  .admin-tag{{display:inline-block;background:#312e81;color:#a5b4fc;border:1px solid #4338ca;
              padding:0.1rem 0.4rem;border-radius:3px;font-size:0.6rem;font-weight:700;
              letter-spacing:0.08em;margin-left:0.3rem;vertical-align:middle}}
  .no-mfa{{color:#f87171;font-weight:600}}
  .weak-mfa{{display:inline-block;background:#422006;color:#fbbf24;border:1px solid #92400e;
             padding:0.15rem 0.45rem;border-radius:3px;font-size:0.72rem;font-weight:600}}
  .strong-mfa{{display:inline-block;background:#052e16;color:#4ade80;border:1px solid #166534;
               padding:0.15rem 0.45rem;border-radius:3px;font-size:0.72rem;font-weight:600}}

  footer{{text-align:center;color:#334155;font-size:0.72rem;margin-top:3rem;
          font-family:'JetBrains Mono',monospace;padding-top:1.5rem;border-top:1px solid #1e293b}}
</style>
</head>
<body>

<header>
  <div class="header-top">
    <div class="logo">🔐</div>
    <h1>M365 Legacy Auth & MFA Reporter <span class="mock-badge">SIMULATED DATA</span></h1>
  </div>
  <div class="meta">
    <span>Generated: {now}</span>
    <span>Tool: mfa_reporter_mock.py</span>
    <span>Tenant: contoso.onmicrosoft.com</span>
    <span>Users scanned: {len(users_with_risk)}</span>
  </div>
</header>

<div class="stats">
  <div class="card total">
    <div class="label">Total Users</div>
    <div class="val">{len(users_with_risk)}</div>
  </div>
  <div class="card high">
    <div class="label">High Risk</div>
    <div class="val">{len(high)}</div>
  </div>
  <div class="card medium">
    <div class="label">Medium Risk</div>
    <div class="val">{len(medium)}</div>
  </div>
  <div class="card low">
    <div class="label">Secure</div>
    <div class="val">{len(low)}</div>
  </div>
  <div class="card nomfa">
    <div class="label">No MFA</div>
    <div class="val">{no_mfa}</div>
  </div>
  <div class="card legacy">
    <div class="label">Legacy Auth</div>
    <div class="val">{legacy}</div>
  </div>
</div>

{section("High Risk Users — Immediate Action Required", "🔴", high)}
{section("Medium Risk Users — Remediate Soon", "🟡", medium)}
{section("Secure Users", "🟢", low)}

<footer>
  mfa_reporter_mock.py &nbsp;|&nbsp; AltSchool Africa Cybersecurity Portfolio &nbsp;|&nbsp;
  White-hat defensive security tool &nbsp;|&nbsp; {now}
</footer>

</body>
</html>"""


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("\n╔══════════════════════════════════════╗")
    print("║  M365 Legacy Auth & MFA Reporter v1.0 ║")
    print("║  AltSchool Cybersecurity Portfolio    ║")
    print("╚══════════════════════════════════════╝\n")

    print("[1/3] Loading simulated M365 user profiles...")
    print(f"      {len(MOCK_USERS)} users loaded.\n")

    print("[2/3] Analysing authentication security...")
    users_with_risk = []
    for u in MOCK_USERS:
        risk, reasons, remediations = assess_user(u)
        users_with_risk.append({
            "user": u, "risk": risk,
            "reasons": reasons, "remediations": remediations
        })

    high   = [x for x in users_with_risk if x["risk"] == "HIGH"]
    medium = [x for x in users_with_risk if x["risk"] == "MEDIUM"]
    low    = [x for x in users_with_risk if x["risk"] == "LOW"]
    no_mfa = [x for x in users_with_risk if not x["user"].get("mfaEnabled")]
    legacy = [x for x in users_with_risk if x["user"].get("legacyAuthProtocols")]

    print(f"      🔴 HIGH:         {len(high)}")
    print(f"      🟡 MEDIUM:       {len(medium)}")
    print(f"      🟢 SECURE:       {len(low)}")
    print(f"      ⚠️  No MFA:       {len(no_mfa)}")
    print(f"      ⚠️  Legacy Auth:  {len(legacy)}\n")

    print("─" * 65)
    print(" PRIORITISED REMEDIATION LIST:")
    print("─" * 65)
    priority = high + medium
    for i, item in enumerate(priority):
        u = item["user"]
        admin = " [ADMIN]" if u.get("isAdmin") else ""
        print(f"\n  [{i+1}] {u.get('displayName','?')}{admin} — {item['risk']}")
        print(f"       {u.get('jobTitle','?')} | {u.get('department','?')}")
        for r in item["reasons"]:
            print(f"       ↳ {r}")
        print(f"       Fix:")
        for rem in item["remediations"]:
            print(f"         → {rem}")
    print("─" * 65)

    print(f"\n[3/3] Generating HTML report...")
    html = generate_report(users_with_risk)
    out  = Path("mfa_report.html")
    out.write_text(html, encoding="utf-8")
    print(f"      ✓ Report saved → {out.resolve()}\n")
    print("  Open mfa_report.html in your browser to view the dashboard.")
    print()


if __name__ == "__main__":
    main()
