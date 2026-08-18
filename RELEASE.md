# ZimaBrain MCP v1.0.7 release record

## Verified deployment

- Host: ZimaBoard2 test system
- Compose file SHA-256: `f99ecd81722a7dfc720c92270ce9306f9a9cce370a44a88bcc20dcb7ca6105a9`
- Final release snapshot: `2026-08-18T06-19-27-823Z-b0c85639`
- Full Brain source commit: `d1add8738146a04b42e7285965f6811467b88e47`
- MCP server image: `local/zimabrain-mcp-zb2:1.0.7`
- UI image: `local/zimabrain-mcp-ui-zb2:1.0.7`

## Runtime verification

- Seven Compose services present and running
- All defined health checks healthy
- Brain, MCP server and UI restart counts: zero
- MCP roadmap self-check: passed
- Six-question quality matrix: 6/6
- Container routing check: passed
- Disk I/O routing check: passed
- UI download and persistence wiring: passed

## Evidence findings are not release failures

At release verification the host evidence reported:

- Homarr unhealthy
- Backups not configured
- One storage-health result requiring attention

These are current NAS findings correctly surfaced by ZimaBrain MCP.
