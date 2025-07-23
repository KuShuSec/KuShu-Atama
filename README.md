# KuShu-Atama

**KuShu-Atama** is a visual mind map project designed to explore strategies in cybersecurity--specifically focusing on attack and defense models. This repository includes both source mind maps and generated artifacts in PDF and PNG formats for easy review and distribution.

---

## 📁 Project Structure

```
KuShu-Atama/
├── artifacts/                   # Exported visualizations (PDF/PNG)
│   ├── Entra_Hybrid_Attack_And_Defence_Collapsed.pdf
│   ├── Entra_Hybrid_Attack_And_Defence_Full.pdf
│   ├── M365_Breakglass_Maturity_Model_v1.1.pdf
│   └── M365_Breakglass_Maturity_Model_v1.2.png
├── src/                         # Source mind maps
│   ├── Entra_Hybrid_Attack_And_Defence.mm
│   ├── Entra_Hybrid_Attack_And_Defence.smmx
│   ├── M365_BreakGlass_Maturity_v1.1.mm
│   └── M365_BreakGlass_Maturity_v1.1.smmx
├── LICENSE
└── README.md
```

---

## 🧠 Mind Maps Included

### 1. Entra Hybrid Attack and Defense Model
This map breaks down hybrid identity attack vectors and corresponding defense strategies across tiers, with visibility into Entra ID, Active Directory, and key integration points.

### 2. M365 Breakglass Maturity Model (v1.1)
A structured matrix model for evaluating the maturity of Microsoft 365 breakglass strategies--from unprepared scenarios to highly resilient, isolated configurations.

**Recent Additions to v1.1:**
- New Level 6: **Isolated Resilience**
- Offline recovery paths: QR codes, printed passphrases
- Scoped CA policy exclusions guidance
- Multi-outage scenario planning (e.g., misconfig, Microsoft outages, attacker lockouts)
- Optional red-tenant or alternate IDP support for breakglass identity paths

This model aligns with Zero Trust principles and includes implementation insights for Conditional Access, PIM, workload identities, and automated detection/resilience patterns.

---

## ✅ How to Use

- Open `.mm` files in [SimpleMind](https://simplemind.eu) or [FreeMind](http://freemind.sourceforge.net/wiki/index.php/Main_Page)
- Open `.smmx` files in [SimpleMind](https://simplemind.eu)
- For Entra Attack & Defend mind map visuals: import to SimpleMind and set diagram type to **Radial**
- For matrix visuals: import to SimpleMind and set diagram type to **Matrix**
- Refer to the `/artifacts` folder for exported, share-ready diagrams in PDF/PNG format

---

## Contributions

Suggestions, edits, or expansions are always welcome--feel free to fork, improve, or discuss via GitHub Issues.

---

## 💣 M365 Breakglass Immaturity Model (v1.0)

This companion model captures common anti-patterns observed in real-world M365 tenants.  
Grouped into four categories:
- 🔥 Fire Hazard
- 🔑 Shared Secrets
- 🕳️ Hidden Traps
- 🙈 We Don't Talk About Breakglass
- 📉 Governance

It’s not a maturity ladder, but a cautionary map of what *not* to do -- based on direct experience and community input.

📄 `artifacts/M365_Breakglass_Immaturity_Model_v1.0.pdf`  
🖼️ `artifacts/M365_Breakglass_Immaturity_Model_v1.0.png`  
🧠 `src/M365_Breakglass_Immaturity_Model_v1.0.mm`  
🧠 `src/M365_Breakglass_Immaturity_Model_v1.0.smmx`

---

## 🙏 Acknowledgements

Huge thanks to the security community for contributions, feedback, and field horrors.  
Special thanks to: David Sass (@sassdawe) and Kay Daskalakis (@kaydaskalakis) who helped refine the models through shared insights.

---

## ⚠️ Note on Use

These models are **not endorsed by Microsoft**. They are practical tools designed to help security teams think critically and defensively about privileged identity design in M365.

Feel free to fork, adapt, or reference them with credit to [KuShuSec](https://github.com/KuShuSec).