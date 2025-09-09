# Selene Telescope

A minimal HTTP API for Selene server listing based on periodic heartbeats from servers.

## Build & Run

```bash
# From this directory
go build .

# Run with defaults: PORT=8080, HEARTBEAT_TTL=60s, PRUNE_INTERVAL=30s
./selene-telescope

# Or with custom settings
PORT=9090 HEARTBEAT_TTL=90s PRUNE_INTERVAL=15s ./selene-telescope
```

Health check:
```bash
curl -s http://localhost:8080/healthz
```

## Configuration

- `PORT` (string): HTTP port to listen on. Default `8080`.
- `HEARTBEAT_TTL` (duration or integer seconds): How long a server is considered alive since its last heartbeat. Default `60s`.
- `PRUNE_INTERVAL` (duration or integer seconds): How often to prune expired servers. Default `30s`.

Durations accept Go duration syntax like `45s`, `2m`, or just integer seconds like `90`.
