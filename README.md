# BreachTracker

Lightweight, front-end incident and compliance control room for practicing data protection, PDPC readiness, and GRC workflows. Built as part of my personal data governance / cybersecurity series.

## Purpose
- Turn abstract policies into a tangible incident lifecycle: detect → triage → contain → resolve → review.
- Practice data classification, lawful handling, and regulator-facing evidence capture without heavyweight tooling.
- Build a portfolio of GRC-focused utilities (this is project 1; next up is VendorGuard for vendor risk).

## What it does
- **Dashboard**: KPIs for open incidents, PDPC risk, severity mix, root-cause heatmaps, and trigger/action patterns derived from incident text.
- **Incident Registry**: Filter/search by severity, unit, status; inline notes, follow-ups, resolution prompts, and one-click detail view.
- **Log New Incident**: Guided form with business unit selection/management, data-type tagging, auto severity suggestion, PDPC/DPO fields, and draft/save.
- **Incident Detail**: Timeline, activity log, attachments, remediation, lessons learned, preventive measures, and improvements.
- **Compliance Board**: Per-business-unit scores, trends, average response, critical counts, recommended actions, and maturity bars.
- **Pattern Signals**: Auto-detects recurring vulnerability classes (phishing, access misconfig, access control, patch gaps, vendor/human error) and top triggers/actions across all incidents to guide risk oversight.
- **SQL Analytics**: In-browser SQL runner (AlaSQL) with prebuilt queries that shrink compliance reporting from hours to minutes; run ad-hoc queries without a backend and export the snapshot.
- **Exports**: Generate PDPC/Audit HTML reports or compliance summaries with full audit trails (timeline, compliance changes, field change history) for sharing and loss-frequency modeling.
- **Persistence**: Uses browser `localStorage`; includes seeded sample incidents to explore the UI. `Reset Data` restores the seed set.

## Tech stack
- Static HTML/CSS/JS (no build step, no backend) with AlaSQL loaded in-browser for SQL analytics.
- State stored in-browser via `localStorage`.
- Optional PostgreSQL-ready schema included in `schema.sql` if you want to wire a backend later.

## Quick start (local)
```bash
# any static server works; Python example
python -m http.server 8000
# then open http://localhost:8000
```

If you prefer, open `index.html` directly in a browser (no dependencies).

## Using the app
- **Tabs**: Dashboard, Incident Registry, Log New Incident, Compliance, and Incident Detail.
- **Create**: Use “Log New Incident”; severity auto-suggests based on record count and data types. You can save as draft or submit.
- **Manage units**: Add/rename/remove business units from the form controls.
- **Resolve**: From registry or detail view, mark resolved and capture lessons learned, preventive measures, and improvements.
- **Compliance**: Review per-unit scores and recommended actions; export data for reporting.
- **SQL Fast Lane**: In the Compliance tab, pick a sample SQL (coverage, throughput, audit trail), run it or paste your own, and export the results—powered by AlaSQL in-browser.
- **Export**: Top-right “Export PDPC Report” or Compliance export generates downloadable HTML summaries.
- **Reset**: “Reset Data” clears local changes and reloads the seeded set.

## Data model
- In-browser: everything is kept in `localStorage` (`breach-tracker-state-v1`).
- Sample data covers multiple breach types, severities, and PDPC states to demo reporting.
- Backend option: `schema.sql` contains tables for incidents, compliance indicators, and DPO guidance (PostgreSQL-ready).

## How this supports data governance & GRC practice
- Embeds data classification (PII, financial, health, credentials) and business-unit ownership in every incident.
- Enforces regulatory fields (PDPC required/under review/notified, DPO guidance) and evidence (timeline, activities, attachments).
- Tracks response time, severity mix, and trends to align with operational risk metrics.
- Produces regulator-ready exports to practice auditability.

## Roadmap (series)
1) **BreachTracker** — incident handling and PDPC readiness (this repo).  
2) **VendorGuard** — vendor risk and third-party breach prevention (next build).  
3) Future ideas: auto-ingest from mailboxes/webhooks, SOC triage queues, richer BI exports, and DB-backed multi-user mode.

## Security & data hygiene
- No API keys, secrets, or live integrations are used; it is a static front-end app.
- Seeded incidents are synthetic; replace with your own test data if you demo publicly.
- State lives in the browser (`localStorage`); nothing is sent off-box unless you export HTML reports.
- If you add a backend using `schema.sql`, keep connection strings and creds in your own env vars, not in the repo.

## Project structure
- `index.html` — shell and tab layout.
- `assets/styles.css` — styling and visual system.
- `assets/app.js` — all app logic (state store, rendering, exports, compliance scoring).
- `schema.sql` — optional database schema.

## Contributing / feedback
This is a personal project; feedback and suggestions are welcome. If you adapt it, credit is appreciated. Feel free to fork and extend (e.g., hook up a backend, add auth, or integrate third-party feeds).
