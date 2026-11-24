# DoorKing Gate Manager — MCP Server (`@rouing/doorking-mcp`)

Model Context Protocol (MCP) server for [DoorKing Gate Manager](https://github.com/rouing/doorking-api). Exposes structured, guarded AI-agent access to DoorKing gates strictly through the REST API — supporting both **local stdio** and **remote Streamable HTTP (OAuth 2.1 + PKCE)** transports.

## Safety & Guardrails

- **Read-only by default:** Working-copy mutations and physical gate operations are disabled unless explicitly opted in via environment variables.
- **Working-copy staging:** Directory and board-setting edits modify the server's local working copy only and never contact physical gate hardware.
- **Explicit diff verification before send:** `send_to_gate` requires the exact `diffHash` returned by `preview_pending_changes` and explicit confirmation.
- **Masked PII by default:** Entry codes and phone numbers are masked in directory search results unless explicitly requested on a single entry.

## Available Tools

### Read-Only (Always Enabled)
- `list_gates`, `get_job_status`
- `search_directory`, `get_resident_details`, `generate_safe_entry_code`
- `query_transactions`, `get_access_insights`, `get_transaction_media_info`
- `preview_pending_changes`, `get_board_settings`
- `list_schedules`, `get_change_history`, `list_past_pulls`, `get_relay_status`
- `list_portal_requests` *(requires user session token, not API key)*

### Working-Copy Writes (`DOORKING_ALLOW_WRITES=true`)
- `upsert_directory_entry`, `delete_directory_entry`
- `update_board_setting_draft`, `discard_working_copy_changes`
- `start_gate_pull` *(read-only DKS Cloud pull of residents or transactions)*
- `review_portal_request` *(requires user session token)*

### Physical Hardware Actions (`DOORKING_ALLOW_PHYSICAL=true`)
- `send_to_gate` *(requires matching `diffHash` from `preview_pending_changes`)*
- `pulse_gate_relay`

## Requirements

- **Node.js:** `>= 24` (runs TypeScript natively with `--experimental-strip-types` / Node 24 built-in TS)
- **Backend:** Running [`doorking-api`](https://github.com/rouing/doorking-api) instance and either a scoped per-gate API key (`dkg_...`) or OAuth sign-in

## Installation

### From GitHub Packages

Configure npm for the `@rouing` scope (`.npmrc`):

```ini
@rouing:registry=https://npm.pkg.github.com
```

Then install globally or run with `npx`:

```bash
npm install -g @rouing/doorking-mcp
```

### From Source

```bash
git clone https://github.com/rouing/doorking-mcp.git
cd doorking-mcp
npm install
```

## Usage

### 1. Local stdio (Claude Desktop, Auggie, Cursor, etc.)

```json
{
  "mcpServers": {
    "doorking": {
      "command": "doorking-mcp",
      "env": {
        "DOORKING_API_URL": "https://gate.example.com",
        "DOORKING_API_KEY": "dkg_your_scoped_api_key",
        "DOORKING_DEFAULT_GATE": "2145550100",
        "DOORKING_ALLOW_WRITES": "true",
        "DOORKING_ALLOW_PHYSICAL": "false"
      }
    }
  }
}
```

### 2. Remote Streamable HTTP (OAuth 2.1 + PKCE)

Start the HTTP server (serves `/mcp`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/register`, `/authorize`, and `/token`):

```bash
DOORKING_API_URL=http://127.0.0.1:8080 \
MCP_PUBLIC_URL=https://gate.example.com \
MCP_ALLOWED_HOSTS=gate.example.com,127.0.0.1,localhost \
MCP_HOST=127.0.0.1 \
MCP_PORT=8081 \
DOORKING_ALLOW_WRITES=true \
npm run start:http
```

Reverse-proxy `/mcp`, `/authorize`, `/token`, `/register`, and `/.well-known/oauth-*` on the same domain as `doorking-api`. Remote MCP clients authenticate interactively with their DoorKing credentials via OAuth 2.1 + PKCE (never storing raw admin API keys on client devices).

### Docker

```bash
docker build -t doorking-mcp .
docker run -p 8081:8081 \
  -e DOORKING_API_URL=http://api:8080 \
  -e MCP_PUBLIC_URL=https://gate.example.com \
  -e MCP_HOST=0.0.0.0 \
  doorking-mcp
```

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `DOORKING_API_URL` | `http://127.0.0.1:8080` | Base URL of `doorking-api` |
| `DOORKING_API_KEY` | *(empty)* | Scoped gate API key (`dkg_...`) for stdio mode (alias: `DOORKING_BEARER_TOKEN`) |
| `DOORKING_DEFAULT_GATE` | *(empty)* | Default gate phone digits when callers omit `phone` |
| `DOORKING_ALLOW_WRITES` | `false` | Enable working-copy write & pull tools |
| `DOORKING_ALLOW_PHYSICAL` | `false` | Enable physical gate tools (`send_to_gate`, `pulse_gate_relay`) |
| `MCP_HOST` | `127.0.0.1` | Bind host for Streamable HTTP mode |
| `MCP_PORT` | `8081` | Bind port for Streamable HTTP mode |
| `MCP_PUBLIC_URL` | `http://127.0.0.1:<port>` | External HTTPS issuer URL for OAuth 2.1 metadata |
| `MCP_ALLOWED_HOSTS` | *(derived)* | Comma-separated allowed `Host` headers for DNS-rebinding protection |

## Development & Tests

```bash
npm run typecheck
node --test
npm run gen:types   # Regenerate OpenAPI TypeScript models via Orval
```

## Related Repositories

- [`rouing/doorking-api`](https://github.com/rouing/doorking-api) — Headless Fastify REST API, DKS Cloud worker & PostgreSQL backend
- [`rouing/doorking-webui`](https://github.com/rouing/doorking-webui) — Standalone React + MUI Progressive Web App
- [`rouing/doorking-android`](https://github.com/rouing/doorking-android) — Native Android app

## Disclaimer

DoorKing Gate Manager is an independent open-source project and is not affiliated with or endorsed by DoorKing, Inc.

## License

MIT
