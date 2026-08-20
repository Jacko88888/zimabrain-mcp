# Security

## Supported security model

ZimaBrain MCP v1.0.8 is a viewer-only, verifier-first release candidate.

- No automatic host mutations
- No direct writable Docker socket
- Restricted Docker socket proxy
- Internal Brain service with no published port
- Read-only root filesystems where supported
- Dropped Linux capabilities for the Brain, MCP server and UI
- `no-new-privileges`
- Bounded evidence collection
- Audit recording and credential redaction
- Explicit approval boundary reserved for future write actions

## Sensitive files

Never commit:

- `.env`
- Secure MCP Tunnel environment files
- API keys or tokens
- Audit and question-history records
- Runtime evidence under `data/`
- Snapshots or support exports
- Private keys and certificates

The release Compose file uses `OPENAI_TUNNEL_ID` and `OPENAI_TUNNEL_ENV_FILE`. Supply them outside source control.

## Host access

The network collector uses host networking and host PID visibility for bounded network and ZimaOS evidence. It remains read-only, drops all capabilities and adds only `NET_ADMIN` and `NET_RAW`.

The storage collector receives only the configured device mappings and read-only host mounts. Confirm device names before deployment because they differ between systems.

## Reporting a security issue

Do not publish credentials, private evidence or exploit details in a public issue. Contact the repository owner privately.
