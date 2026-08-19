# ZimaBrain MCP v1.0.8 release candidate

## Release-candidate scope

- Host: portable ZimaOS deployment; clean-install validation pending on ZimaBoard
- Release-candidate Compose SHA-256: `e64fefe09bffbaef6b64c329107fc5b6b27f465b5bef48f612b786cdffc6e8b4`
- Full Brain source commit: `d1add8738146a04b42e7285965f6811467b88e47`
- MCP server image: `local/zimabrain-mcp:1.0.8-portable`
- UI image: `local/zimabrain-mcp-ui:1.0.8-portable`

## Validation before merge

- JavaScript syntax checks
- Installer shell syntax check
- Compose structure and security assertions
- Dynamic-hostname rendering test using `system.hostname`
- Clean source download and build on ZimaBoard
- Six containers healthy with expected port publication
- UI, MCP health, question answering, history, downloads and audit checks

The release candidate must not be merged into `main` until the clean ZimaBoard installation and runtime checks pass.

## Portable-host fixes

- The interface uses the hostname returned by live MCP system evidence.
- The Compose backend permits ZimaOS to publish the UI and loopback MCP ports.
- The installer checks available `/DATA` space before building.
- The installer reports a usable default-route IPv4 address when available.
