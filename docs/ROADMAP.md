# Project SENTINEL - Delivery Roadmap

This roadmap turns the original vision into a tracked execution plan. It is meant to answer two questions quickly:

1. What is already real in the repo?
2. What are we building next?

Status key:

- `[done]` implemented and usable in the repo
- `[partial]` present but incomplete, simulated, or not production-safe
- `[todo]` not implemented yet
- `[active]` currently being built
- `[blocked]` waiting on architecture, platform, or dependency decisions

---

## Current Position

### Product maturity

- Current state: early MVP / prototype
- Target state: deployable offline-capable home / SMB network defense platform
- Repo priority: replace simulated or placeholder security features with real system integrations

### What exists today

- `[done]` FastAPI backend with REST and WebSocket entrypoints
- `[done]` React dashboard with core views
- `[done]` Nmap-backed device discovery and port scanning
- `[done]` local risk/vulnerability heuristics and CVE lookup dataset
- `[done]` local LLM integration for NLP parsing and honeypot analysis
- `[done]` honeypot service framework with attack logging
- `[partial]` anomaly detection
- `[partial]` auto-defense
- `[partial]` DNS filtering
- `[partial]` topology visualization
- `[partial]` security middleware / request protection
- `[todo]` real packet capture / IDS / IPS
- `[todo]` gateway mode / transparent firewall mode
- `[todo]` secure plugin sandboxing
- `[todo]` endpoint agents
- `[todo]` auth + RBAC maturity
- `[todo]` packaging and deployment

---

## Master Tracker

| Area | Status | Notes |
|------|--------|-------|
| Recon and device discovery | `[done]` | ARP + Nmap scanning is functional |
| Vulnerability correlation | `[partial]` | Static/local CVE data, not full feed sync |
| Natural-language control | `[partial]` | Works, but limited intents and little state |
| Real-time traffic monitoring | `[partial]` | Scapy-backed live capture is now wired in and traffic/defense snapshots stream live over websocket, but deeper analytics and platform-specialized adapters still remain |
| Anomaly detection | `[partial]` | Isolation Forest + rules exist, but only shallow telemetry |
| Auto-defense | `[partial]` | Firewall adapter layer, persisted block state, quarantine controls, response playbooks, device-level containment metadata, profile-aware containment semantics, critical-service isolation, allowlist-based restricted containment, named segment isolation, per-segment policy defaults, behavior-aware segment overrides, telemetry-aware segment overrides, event-history thresholds, and decision-trace-backed policy ordering are now in place, but stronger network-aware policy still remains |
| DNS sinkholing | `[partial]` | Persisted blocked domains, hosts-file preview/sync, a lightweight local UDP resolver with upstream forwarding, autostart-aware conflict checks, broader blocked-query handling, and guided deployment presets are now in place, but a hardened production resolver path still remains |
| Honeypot and analysis | `[partial]` | Functional service trap, not full Dionaea/Cowrie integration |
| Plugin architecture | `[partial]` | Built-in stubs only, no sandbox or trust model |
| Authentication and authorization | `[partial]` | Viewer/operator/admin token roles and action-level authorization are now partly implemented, but full user management and richer RBAC policy still remain |
| Audit integrity | `[partial]` | Security events and defense history now persist and stream live to the UI; tamper-evident chaining and export still remain |
| Cross-platform network control | `[todo]` | Needs Linux gateway mode and Windows monitor mode split |
| Packaging | `[todo]` | No AppImage / MSI / service installers yet |

---

## Phase Plan

## Phase 1 - Control Plane Hardening

Goal: make SENTINEL safe enough to grow.

- `[done]` Add local operator authentication for API and dashboard
- `[todo]` Add role model: viewer / operator / admin
- `[todo]` Protect destructive actions behind explicit privilege checks
- `[done]` Add settings persistence instead of frontend-only mock settings
- `[partial]` Add audit entries for every security-sensitive action
- `[todo]` Add safer secret/config handling

Definition of done:

- API control endpoints are protected
- Dashboard can authenticate locally
- High-risk operations are logged
- Security settings are persisted and reviewable

## Phase 2 - Real Telemetry Pipeline

Goal: replace simulated monitoring with real traffic observation.

- `[done]` Add first live packet capture backend using Scapy
- `[todo]` Linux backend: libpcap / tcpdump / Suricata integration
- `[todo]` Windows backend: Npcap-based monitoring integration
- `[todo]` Normalize captured traffic into a shared event model
- `[todo]` Track top talkers, protocol breakdown, suspicious flows, and scan patterns
- `[done]` Replace fake traffic monitor data in UI with live capture stats and error reporting

Definition of done:

- Monitor view shows real packet/flow-derived data
- Suspicious events come from observed traffic rather than random generation
- Telemetry can drive anomaly detection and response

## Phase 3 - Defensive Enforcement

Goal: make SENTINEL capable of real containment.

- `[done]` Refactor firewall engine into safe platform adapters
- `[partial]` Linux adapter: iptables/nftables/UFW strategy
- `[done]` Windows adapter: firewall rules with safer naming and lifecycle
- `[partial]` Add quarantine semantics beyond simple IP blocking
- `[partial]` Add response playbooks for brute force, scanning, SMB/RDP exposure, and honeypot hits
- `[todo]` Add dry-run / simulation mode for risky actions

Definition of done:

- Defensive actions are auditable, reversible, and scoped
- Firewall operations are consistent across supported modes
- Auto-defense can execute trusted playbooks

## Phase 4 - Detection and Explainability

Goal: improve decision quality and transparency.

- `[todo]` Add telemetry-derived features for anomaly scoring
- `[todo]` Expand model training workflow and persisted model lifecycle
- `[todo]` Add SHAP/LIME-backed explanation layer where feasible
- `[todo]` Show why a device or flow was flagged
- `[todo]` Add confidence and false-positive review workflow

Definition of done:

- Alerts show the triggering evidence
- Models are trainable and reloadable
- Analysts can review why a block or alert occurred

## Phase 5 - Shield Mode

Goal: move from host-centric monitoring to LAN guardian mode.

- `[todo]` Linux gateway mode
- `[todo]` Transparent bridge / monitor mode
- `[todo]` DNS sinkhole / resolver workflow
- `[todo]` Router integration guidance and validation
- `[todo]` Home-lab deployment profile

Definition of done:

- Linux deployment can inspect and enforce for LAN traffic
- DNS filtering and flow monitoring operate as part of the network path
- Setup flow makes gateway vs monitor mode explicit

## Phase 6 - Extensibility and Agents

Goal: make SENTINEL safely expandable.

- `[todo]` Replace stub plugin manager with manifest-based plugin system
- `[todo]` Add plugin permissions and sandbox boundaries
- `[todo]` Add signed/trusted plugin policy
- `[todo]` Add endpoint agent design for Windows and Linux
- `[todo]` Add agent telemetry ingestion

Definition of done:

- Third-party modules run within clear guardrails
- Endpoint agents can report telemetry without breaking the trust model

## Phase 7 - Packaging and Release

Goal: make the system installable and repeatable.

- `[todo]` Add Docker/dev container support
- `[todo]` Add Windows service and installer workflow
- `[todo]` Add Linux service + package workflow
- `[todo]` Add portable configs and deployment profiles
- `[todo]` Add backup/export/import for settings and rules

Definition of done:

- SENTINEL can be installed with documented production-ish flows
- Common deployment modes are reproducible

---

## Immediate Build Queue

These are the next concrete tasks we should burn down in order.

1. `[active]` Deepen containment from decision-trace-backed policy ordering into richer network-aware policies
2. `[done]` Wire playbooks into honeypot and middleware-specific triggers instead of generic callbacks
3. `[todo]` Add real DNS resolver/sinkhole mode
4. `[partial]` Add viewer / operator / admin roles
5. `[partial]` Add event streaming from telemetry to UI
6. `[todo]` Add tamper-evident event chaining and export

---

## Progress Log

### 2026-04-01

- `[done]` Roadmap rewritten into a delivery tracker
- `[done]` Began Phase 1 hardening work
- `[done]` Implemented local operator authentication for `/api/v1/*` via `SENTINEL_AUTH_TOKEN`
- `[done]` Added dashboard token storage and verification flow in Settings
- `[done]` Replaced the simulated traffic monitor with a Scapy-backed live capture monitor
- `[done]` Updated the monitor UI to expose capture mode, bytes, top talkers, and capture errors
- `[done]` Added a firewall adapter layer with safer Windows/Linux execution boundaries
- `[done]` Added persisted blacklist tracking and adapter diagnostics in the defense API/UI
- `[done]` Added persistent system settings API and dashboard integration
- `[done]` Added persisted security-event history for monitor and defense actions
- `[done]` Added Linux adapter discovery with nftables/UFW/iptables support ordering
- `[done]` Added quarantine API and dashboard controls for containment actions
- `[done]` Added auditable defense playbooks for critical risk, elevated risk, port scans, SMB/RDP exposure, and honeypot hits
- `[done]` Wired security middleware, traffic monitor, and honeypot callbacks into named defense playbooks
- `[done]` Added device-level containment metadata with profile and scope tracking for quarantine state
- `[done]` Added profile-aware containment semantics so restricted vs full isolation produce different adapter rule sets
- `[done]` Added critical-service isolation so adapters can target SMB/RDP-style ports without fully cutting off a device
- `[done]` Added allowlist-based restricted containment with configurable allowed segments and destinations
- `[done]` Added named segment isolation so devices can be pinned to their detected network zone during containment
- `[done]` Added per-segment containment policies so `users`, `iot`, and `guest` zones can default to different profiles
- `[done]` Added behavior-aware segment overrides so risky ports or trusted-device status can change segment containment defaults
- `[done]` Added telemetry-aware segment overrides so live signals like failed logins and scan bursts can change segment containment defaults
- `[done]` Added event-history thresholds so repeated triggers inside a time window can escalate segment containment
- `[done]` Added ordered containment decision tracing so segment defaults, conditions, thresholds, and final selections are visible in the UI and event history
- `[done]` Added viewer/operator/admin token roles with route-level privilege checks for destructive API actions
- `[done]` Lazy-loaded major frontend panels to start reducing the main bundle pressure
- `[done]` Added live websocket streaming for persisted security events so monitor views update without waiting for the poll loop
- `[done]` Surfaced configured auth roles and current verified role in the settings UI
- `[done]` Added a managed DNS sinkhole workflow with persisted blocked domains, hosts preview, and hosts-file sync controls
- `[done]` Added a lightweight local DNS sinkhole resolver with upstream forwarding, autostart-aware conflict checks, setup guidance, and live traffic/defense/DNS websocket telemetry
- `[done]` Added dashboard startup-status cards, broader blocked DNS query handling, and guided router/client deployment presets
- `[active]` Next implementation target: add richer network-aware policies beyond current ordered threshold-based containment

---

## Risks and Truths

- The current repo is not yet the full “Wakandan Shield” system
- Real packet capture and enforcement are the largest engineering step remaining
- Cross-platform support should intentionally diverge by mode:
  - Linux: preferred for gateway / firewall / transparent bridge operation
  - Windows: preferred for monitor / analyst workstation / host defense mode
- Safety matters more than feature count for automated defense actions

---

## Completion Criteria For The Vision

SENTINEL will count as “fully built” against the original brief when all of the following are true:

- Real network telemetry is captured on supported platforms
- Shield mode can observe and enforce on LAN traffic in Linux deployment
- Dashboard, NLP, and response actions operate against real telemetry
- Auth, RBAC, and audit logging protect the control plane
- DNS filtering, honeypot, anomaly detection, and playbooks work together
- Packaging exists for repeatable local deployment
- Documentation reflects actual behavior, not aspirational behavior

---

*Last updated: April 1, 2026*
