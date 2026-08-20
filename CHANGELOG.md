# Changelog

## v1.0.8 - 2026-08-19

- Detects the live ZimaOS hostname through MCP evidence and uses it throughout the UI.
- Restores LAN port publication on ZimaOS by using a non-internal Compose bridge.
- Adds a 6 GiB `/DATA` free-space preflight for clean source builds.
- Prints a usable UI address using the default-route IPv4 address with safe fallbacks.
- Aligns UI, MCP health, dashboard and image version labels at v1.0.8.
- Replaces the single-source LAN answer with combined listener, firewall, Docker-port, application-mount, interface and security-scan evidence.
- Distinguishes potentially LAN-accessible listening binds from connection-tested LAN reachability.
- Corrects `service_only` to mean the ZFW service is running without verified active hooks or saved enabled rules.
- Adds claim-level network-answer tests and full source-manifest hash verification.
- Repairs stale release security tests that referenced removed Compose filenames.
- Detects and mounts the optional saved ZFW rules file read-only when it exists on the target host.
- Routes “What needs attention?” through the comprehensive evidence layer and gathers Docker, service, storage, disk-health, network and security evidence together.
- Prevents uncollected legacy fields and clear failed-service evidence from becoming false media-path or systemd findings.
- Marks comprehensive answers partially verified whenever required SMART/NVMe or network-reachability evidence remains unverified.
- Supports both branch names and exact 40-character commit SHAs in the portable installer archive URL.
- Detects the target host timezone for Compose and the UI, removes the Sydney default and replaces the developer-specific `GH` avatar with a neutral local-viewer symbol.
- Separates verified host timezone from the browser viewer timezone and supports explicit IANA timezone overrides.
- Routes CPU, memory, uptime, load and timezone questions through live host evidence; missing requested fields now force PARTIALLY VERIFIED.
- Inspects bounded Docker configuration evidence for privileged mode, Docker-socket access, host PID/network namespaces and added capabilities; zero successful inspections now force NOT VERIFIED.
- Adds official top-level `x-casaos` identity metadata while documenting that direct Docker Compose installs remain external Legacy apps until a validated Custom App installation path is used.

## v1.0.7 - 2026-08-18

- Connected the full ZimaBrain engine to live MCP evidence.
- Added 34 approved read-only MCP tools.
- Added Docker, storage, network and ZimaOS evidence collectors.
- Added direct readable conclusions before detailed reasoning.
- Added evidence provenance and verification states.
- Added persistent question history.
- Added current-answer and full-session downloads in Markdown, HTML and JSON.
- Added redacted support-report export.
- Added Evidence, Tool registry, Approvals and Audit ledger views.
- Improved proportional full-width layout and typography.
- Corrected application matching and Homarr diagnostics.
- Corrected comprehensive-health and container-health classification.
- Corrected disk inventory, disk-health and LAN exposure answers.
- Added eight-route answer-quality self-tests.
- Aligned release image tags and Secure MCP Tunnel metadata.
- Verified the seven-service Compose policy and final runtime health.
