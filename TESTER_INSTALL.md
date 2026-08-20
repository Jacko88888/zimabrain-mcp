# ZimaBrain MCP portable ZimaOS tester installation

This installer is intended for clean-install validation of ZimaBrain MCP v1.0.8.

It downloads the public release into `/DATA/AppData/zimabrain-mcp`, detects the host's supported SATA and NVMe disks, creates an exact read-only Docker device allow-list, validates the generated Compose configuration, builds the release images locally and starts the six local services.

The installer does not enable the optional Secure MCP Tunnel. Tunnel enrolment requires a separate tunnel identifier and environment file for each tester. The local ZimaBrain MCP interface and all local evidence tools operate without the tunnel.

## Install

Run as `root` in the ZimaOS terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/Jacko88888/zimabrain-mcp/main/install-zimaos.sh | sh
```

If `curl` is unavailable:

```bash
wget -qO- https://raw.githubusercontent.com/Jacko88888/zimabrain-mcp/main/install-zimaos.sh | sh
```

After installation, open:

```text
http://ZIMAOS-IP:8621
```

The installer reports the detected host timezone. To test with an explicit IANA timezone when the host itself is configured as UTC, prefix the installer with `ZIMABRAIN_TZ=Europe/Berlin` (or the tester's correct zone). The UI labels host and viewer timezones separately if they differ.

Because this tester installer uses Docker Compose directly in order to detect and safely map each host's storage devices, ZimaOS can show the six containers under Legacy apps. They are one Compose project, but they are not yet registered as one ZimaOS dashboard application. The source includes `x-casaos` metadata for the forthcoming validated Custom App package.

## What the installer verifies

- It is running as `root`.
- Docker and Docker Compose are available.
- The required host utilities are available.
- At least one supported SATA or NVMe disk is present.
- Every exposed storage device exists as a block device.
- The final merged Compose configuration is valid before any service is started.

## Persistent data

Runtime data is stored under:

```text
/DATA/AppData/zimabrain-mcp/data
```

Re-running the installer updates the application source without deleting this directory.

## Safety boundary

- Docker access is restricted through a read-only socket proxy.
- Storage devices are detected and individually mapped read-only.
- The installer does not use `privileged: true`.
- The Brain, MCP server and UI drop all Linux capabilities.
- The application performs no automatic write actions.
