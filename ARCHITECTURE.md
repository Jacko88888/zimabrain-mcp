# Architecture

## Request flow

1. The browser sends a question to the ZimaBrain MCP UI.
2. The MCP server classifies the question and requests only the required evidence.
3. Bounded collectors obtain current Docker, storage, network or ZimaOS evidence.
4. The full ZimaBrain engine reasons over the same evidence report.
5. The MCP server verifies the answer, attaches provenance and records the request.
6. The UI renders a direct conclusion followed by evidence and reasoning.

## Services

| Service | Purpose | Exposure |
|---|---|---|
| `ui` | Web interface and downloads | LAN port 8621 |
| `mcp-server` | MCP tools, orchestration and verification | Loopback 8790 and internal backend |
| `brain` | Full ZimaBrain reasoning | Internal backend only |
| `docker-proxy` | Restricted Docker read API | Internal backend only |
| `storage-collector` | SMART, NVMe, Btrfs, RAID and mount evidence | Internal backend only |
| `network-collector` | Network and ZimaOS host evidence | Host network, bounded socket |
| `tunnel-live` | Secure MCP Tunnel client | Loopback health port 8791 and egress |

## Trust boundaries

- The Brain does not receive the Docker socket.
- The MCP server talks to Docker through a restricted proxy.
- Host evidence mounts are read-only.
- Collector output is bounded before it reaches the reasoning layer.
- Runtime state is stored under `/DATA/AppData` and is excluded from source control.
- Answers retain verification state and evidence-source metadata.

## Full Brain provenance

The release contains the full Brain source captured from commit:

`d1add8738146a04b42e7285965f6811467b88e47`

The image build verifies the source manifest and imports the Brain modules before completing.
