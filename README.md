# ZimaBrain MCP

**Verifier-first ZimaBrain reasoning with live, read-only MCP evidence for ZimaOS.**

ZimaBrain MCP combines the full ZimaBrain diagnostic engine with bounded live evidence collectors for Docker, storage, networking, ZimaOS health and application state. Answers begin with a direct readable conclusion, then show verification status, reasoning, evidence sources and the safest next step.

## Release

- Version: **1.0.8 release candidate**
- Candidate branch: [`agent/v1.0.8-portable-host-detection`](https://github.com/Jacko88888/zimabrain-mcp/tree/agent/v1.0.8-portable-host-detection)
- Status: portable six-service deployment verified healthy on ZimaBoard; the latest comprehensive-health correction is awaiting its clean runtime retest
- Main source status: **1.0.7 remains unmerged until the v1.0.8 runtime gate passes**
- MCP tools: **34 read-only capabilities**
- Services: **6 local services**; optional Secure MCP Tunnel is separate
- Full Brain source commit: `d1add8738146a04b42e7285965f6811467b88e47`
- MCP integration patchsets: `mcp-structured-network-evidence-v1`, `mcp-structured-comprehensive-health-v1` and `mcp-evidence-completeness-v1` (recorded with updated hashes in the source manifest)

## Architecture

```text
Browser UI :8621
      |
      v
ZimaBrain MCP server
      |---- Full ZimaBrain reasoning engine
      |---- Docker socket proxy (restricted read-only API)
      |---- Storage collector (read-only host evidence)
      |---- Network/ZimaOS collector (bounded host evidence)
      |
      v
Secure MCP Tunnel
```

The Brain is internal only. It has no published port and receives live evidence through the MCP server. The UI is the only LAN-facing component in the release Compose file.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## What it answers

The release-candidate answer matrix covers:

1. Physical disk inventory
2. SMART, NVMe and RAID health
3. Evidence-backed attention findings
4. Backup status
5. LAN listening services and exposure
6. Application verification, including Homarr
7. Running and stopped containers
8. Live container block I/O
9. Current CPU usage, memory usage, uptime, load and host timezone
10. Privileged mode, Docker-socket access, host namespaces and added container capabilities

The verifier rule is simple:

> No evidence means no claim.

## Interface

The ZimaBrain MCP interface includes:

- Command centre
- Ask ZimaBrain
- Evidence and provenance
- Tool registry
- Approval boundary
- Audit ledger
- Persistent question history
- Current-answer downloads in Markdown, HTML and JSON
- Full-session downloads in Markdown, HTML and JSON
- Redacted support-report export

## Security model

- Viewer-only release
- Per-tool read boundaries
- Restricted Docker socket proxy
- Project-scoped backend bridge; only the UI is LAN-published and MCP is loopback-published
- Read-only container root filesystems where supported
- `cap_drop: ALL` for the Brain, MCP server and UI
- `no-new-privileges`
- Bounded evidence collection
- Audit recording
- Credential redaction
- No automatic write actions
- Approval-gated future action layer

Runtime data, audit records, question history, snapshots, credentials, tunnel environment files and `node_modules` are intentionally excluded from this repository.

## Requirements

- ZimaOS or a compatible Linux Docker host
- Docker Engine with Compose
- Access to the required read-only host evidence paths
- A configured Secure MCP Tunnel environment file when tunnel access is required
- Supported storage devices configured in the Compose file

## Configuration

Copy the example environment file and set the tunnel identifier outside source control:

```bash
cp .env.example .env
```

The portable release definition is [compose.portable.yaml](compose.portable.yaml). The installer creates `compose.detected-devices.yaml` locally from the target host's actual SATA and NVMe devices; that generated file is not committed.

The installer detects the host timezone from an explicit `ZIMABRAIN_TZ` override, the existing `TZ` environment, `timedatectl`, `/etc/timezone`, or `/etc/localtime`, in that order. The interface shows the verified host timezone and, when different, labels the browser's viewer timezone separately. This prevents a browser location from being presented as the server timezone.

The Compose source now contains the official top-level `x-casaos` identity and entry metadata for one ZimaBrain MCP application. A terminal `docker compose` installation is still external to ZimaOS app management, so ZimaOS may list its containers under Legacy apps. Registering it as one dashboard tile requires a separately validated ZimaOS Custom App/App Store installation path; the installer does not call an unverified app-management API.

`compose.zb2-v0.10.yaml` is retained as the original ZimaBoard2 development topology and is not the portable installer target.

## Validation performed

The v1.0.8 release candidate retains the v1.0.7 validation suite and adds portable-host and claim-level checks:

- Six-service portable Compose validation
- Full Brain import and source-manifest verification
- Per-file Full Brain source size and SHA-256 verification during image build
- Eight answer-route evidence alignment checks
- Claim-level network tests that prevent listening binds from being called verified LAN reachability
- Cross-source network answers using listeners, ZFW state, Docker ports, application mounts, interfaces and the bounded security scan
- Comprehensive-attention regression tests preventing uncollected media paths or clear systemd evidence from becoming findings
- Partial-verification enforcement when SMART, NVMe, LAN-probe or internet-reachability evidence is incomplete
- **40 Node tests and 14 dependency-free Python/security tests passed** for the current candidate source
- Docker, storage, network and ZimaOS tool self-checks
- UI JavaScript syntax verification
- Download-handler verification
- Question-history persistence wiring
- Security-boundary inspection
- Six v1.0.8 containers and their health checks were verified on ZimaBoard before the latest Brain-answer correction
- A clean runtime retest of the latest candidate remains required before merging into main

## Repository layout

```text
brain-runtime/       Full ZimaBrain bridge and pinned source
mcp-server/          MCP tools, evidence orchestration and answer routing
network-collector/   Network and ZimaOS evidence collector
storage-collector/   Storage, SMART, NVMe, Btrfs and RAID evidence
ui/runtime/          ZimaBrain MCP web interface
Dockerfile.*         Reproducible service images
compose.portable.yaml
install-zimaos.sh
```

## Safety

This project intentionally defaults to read-only analysis. Do not grant broader host access, writable Docker socket access, or privileged mode without a separate threat review and explicit approval design.

## Licence

No open-source licence has been granted. All rights are reserved unless a licence is added later.
