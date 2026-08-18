# ZimaBrain MCP

**Verifier-first ZimaBrain reasoning with live, read-only MCP evidence for ZimaOS.**

ZimaBrain MCP combines the full ZimaBrain diagnostic engine with bounded live evidence collectors for Docker, storage, networking, ZimaOS health and application state. Answers begin with a direct readable conclusion, then show verification status, reasoning, evidence sources and the safest next step.

## Release

- Version: **1.0.7**
- Status: verified on ZimaBoard2
- MCP tools: **34 read-only capabilities**
- Services: **7**
- Full Brain source commit: `d1add8738146a04b42e7285965f6811467b88e47`
- Verified release snapshot: `2026-08-18T06-19-27-823Z-b0c85639`

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

The verified release matrix covers:

1. Physical disk inventory
2. SMART, NVMe and RAID health
3. Evidence-backed attention findings
4. Backup status
5. LAN listening services and exposure
6. Application verification, including Homarr
7. Running and stopped containers
8. Live container block I/O

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
- Internal backend network
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

The canonical deployment definition is [compose.zb2-v0.10.yaml](compose.zb2-v0.10.yaml).

Review device mappings and host paths before deployment. Storage devices and mount sources differ between systems.

## Validation performed

The v1.0.7 release passed:

- Seven-service Compose policy validation
- Full Brain import and source-manifest verification
- Eight answer-route evidence alignment checks
- Docker, storage, network and ZimaOS tool self-checks
- UI JavaScript syntax verification
- Download-handler verification
- Question-history persistence wiring
- Security-boundary inspection
- Image and running-container tag verification
- Zero restart count for the Brain, MCP server and UI at release verification

## Repository layout

```text
brain-runtime/       Full ZimaBrain bridge and pinned source
mcp-server/          MCP tools, evidence orchestration and answer routing
network-collector/   Network and ZimaOS evidence collector
storage-collector/   Storage, SMART, NVMe, Btrfs and RAID evidence
ui/runtime/          ZimaBrain MCP web interface
Dockerfile.*         Reproducible service images
compose.zb2-v0.10.yaml
```

## Safety

This project intentionally defaults to read-only analysis. Do not grant broader host access, writable Docker socket access, or privileged mode without a separate threat review and explicit approval design.

## Licence

No open-source licence has been granted. All rights are reserved unless a licence is added later.
