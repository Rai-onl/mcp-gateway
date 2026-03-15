# MCP Gateway

HTTP gateway for Model Context Protocol servers. Routes MCP requests to backend server runtimes, bridging stdio-based servers to Streamable HTTP and proxying remote MCP endpoints through a single authenticated entry point.

## Architecture

```mermaid
flowchart TB
    client["MCP client<br/>(Claude Code, Codex, etc.)"]
    client -->|"Streamable HTTP"| gateway

    subgraph gateway["MCP Gateway"]
        router["Router"]
        router --> bridge["Stdio bridge"]
        router --> proxy["HTTP proxy"]
    end

    bridge --> local["Local MCP process<br/>(stdin/stdout)"]
    proxy --> upstream["Remote MCP server<br/>(HTTP)"]
```

The gateway accepts MCP requests over Streamable HTTP and dispatches them to the appropriate backend runtime:

- **Stdio bridge** — spawns a local MCP server process, performs the MCP handshake, and translates between HTTP and stdin/stdout.
- **HTTP proxy** — forwards requests to a remote MCP server endpoint with header injection.

## Development

```sh
cargo build
cargo test
cargo clippy --all-targets
cargo fmt
```

The project uses tabs for indentation (configured in `rustfmt.toml`).

## Licence

LGPL-3.0-or-later
