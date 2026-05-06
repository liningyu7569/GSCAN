# Going_Scan — Complete Technical Reference

> Version: V2 Engine | Date: 2026-05-04 | Language: Go 1.24+

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [GS Engine](#3-gs-engine)
4. [gping Probe Engine](#4-gping-probe-engine)
5. [UAM Unified Asset Model](#5-uam-unified-asset-model)
6. [CLI Command Reference](#6-cli-command-reference)
7. [Data Flows & Lifecycles](#7-data-flows--lifecycles)
8. [Package Structure & Source Navigation](#8-package-structure--source-navigation)
9. [Key Design Decisions](#9-key-design-decisions)
10. [Build & Test](#10-build--test)

---

## 1. Project Overview

### 1.1 Definition

Going_Scan (binary name `goscan`) is a high-performance network asset scanning and analysis platform written in Go. It consists of three cooperating subsystems:

| Subsystem | Full Name | Role |
|-----------|-----------|------|
| **GS** | Going_Scan | High-speed L4/L7 asset discovery engine |
| **gping** | gping | Multi-route targeted verification probe engine |
| **UAM** | Unified Asset Model | Unified asset contract layer and knowledge hub |

### 1.2 Design Philosophy

The goal is not simply "a better scanner" but a complete asset reconnaissance and verification workflow:

1. GS rapidly discovers assets
2. UAM persists asset state
3. gping performs targeted verification, confirmation, and correction
4. Specialized scans perform deep protocol analysis
5. Ultimately forms a traceable, verifiable, extensible asset hub

### 1.3 vs. Traditional Scanners

- Traditional: throughput-first → coarse results; or depth-first → slow
- Going_Scan: separates L4 discovery from L7 identification; UAM provides knowledge persistence instead of one-shot output
- gping upgrades "scan and leave" to "scan → confirm → persist → re-verify" closed loop

---

## 2. Architecture Overview

### 2.1 Three-Tool Relationship

`goscan` provides a unified CLI with three subcommands (`scan`, `gping`, `uam`), each corresponding to a subsystem. All three share a single SQLite database (uam.db) as their data exchange hub.

**GS (scan command)** handles stateless L4 scanning and L7 service identification, producing initial asset facts (hosts, ports, services). During scanning, results are asynchronously written to UAM via hooks (uam_hook.go) as Observations, Claims, and Projections.

**gping** handles targeted verification, reading asset context from UAM as target sources, executing Raw/Stack/App three-route probing. Results are written back to UAM via GPingIngester.

**UAM** serves as the data hub, storing all asset state in SQLite. It never sends packets or probes — only manages asset identity, observation storage, claim normalization, projection maintenance, and query/reporting.

The closed loop: GS discovers → UAM persists and manages → gping verifies and corrects → results write back to UAM forming updated asset views.

### 2.2 Directory Structure

```
cmd/                        CLI command definitions (Cobra)
  root.go                   Main command + scan subcommand
  gping.go                  gping command and subcommands
  uam.go                    uam query commands

pkg/                        Shared libraries (externally referenceable)
  conf/                     Global config and timing templates
  core/                     L4/L7 engine core
  l7/                       L7 service detection and nmap probe parsing
  routing/                  Route, gateway, ARP resolution
  target/                   Target iterators (CIDR, IP ranges)
  queue/                    Lock-free ring buffer
  metrics/                  Sharded metric counters
  util/                     Checksums and utilities

internal/                   Internal implementation (not exposed)
  gping/                    Complete gping implementation
    templates/              16 built-in YAML templates
  uam/                      Complete UAM implementation
    domain/                 Domain types and constants
    normalize/              GS/gping/Module result normalization
    project/                Projection refresh engine
    service/                Ingestion, query, report services
    store/sqlite/           SQLite storage layer
```

---

## 3. GS Engine

### 3.1 Core Data Structures

**EmissionTask** (8-byte compressed scan task):

```go
type EmissionTask struct {
    TargetIP        uint32 // Target IPv4 (big-endian)
    TargetPort      uint16 // Target port
    RouteID         uint16 // Global route table index
    Protocol        uint8  // IPPROTO_TCP / UDP / ICMP
    ScanFlags       uint8  // TCP flags (SYN=0x02, ACK=0x10...)
    ScanKind        uint8  // Scan method: SYN/ACK/Window/UDP
    IsHostDiscovery bool   // Host discovery flag
}
```

Exactly 8 bytes (64 bits), efficiently passed through concurrent channels.

**PacketTensor** (32-bit reply feature):

```go
type PacketTensor uint32

// Bit layout:
// bits 0-7   : TCP Flags / ICMP Type / UDP virtual flag
// bits 8-15  : IP TTL
// bits 16-19 : TCP Window quantized / ICMP Code
// bits 20-27 : IP Protocol
// 0xFFFFFFFF : Timeout sentinel
```

`ExtractTensor()` performs O(1) packet collapse in the receiver. Companion methods (`IsTCPStateOpen()`, `IsTCPStateClosed()`, `IsTCPFiltered()`, `IsUDPStateOpen()`, `IsUDPStateClosed()`, `IsHostAlive()`) all use pure bitwise operations for state classification.

**RouteMeta** (L2/L3 physical link info):

```go
type RouteMeta struct {
    SrcIP  uint32   // Source IP
    SrcMAC [6]byte  // Local NIC MAC
    DstMAC [6]byte  // Next-hop MAC
}
```

Accessed via `GlobalRouteCache` slice + `RouteID` index for O(1) lookup, supporting multi-NIC/multi-gateway scenarios.

### 3.2 Engine Runtime

On startup, the Engine creates three background goroutines:

- **runSendPacer**: Rate-control token generator, replenishing the sendTokens channel at configured pps
- **RunDispatcher**: pcap receive loop, continuously reading replies from the NIC, performing Channel ID decoding, target verification, tensor collapse, and result delivery
- **RunL7Dispatcher**: L7 service detection consumer loop, pulling open-port results from GlobalResultBuffer and distributing to worker pool

The main loop retrieves task batches from TaskGenerator, and for each task:

1. Acquires a token from Tokens channel (CWND concurrency control)
2. Acquires an available channelID from FreeIDs channel
3. Launches a goroutine to execute LaunchProbe

LaunchProbe execution flow:

- Retrieves route info (source IP, MAC addresses) from GlobalRouteCache
- Acquires rate-control token via waitSendTurn
- Calls BuildIntoBuffer to construct complete packet on pooled memory
- Sends packet via pcap.WritePacketData
- Enters select: channels[id] receives PacketTensor on success; timer fires on timeout (retry or mark filtered)
- On success: increaseCWND + updateRTO; on failure: decreaseCWND
- evaluateTaskResult maps tensor to port state; emitScanResult writes to result buffer

### 3.3 CWND Adaptive Concurrency

- **increaseCWND()**: On successful reply, attempts to place one token into Tokens channel, `currentCapacity +1`
- **decreaseCWND()**: On timeout, attempts to drain `currentCapacity/2` tokens from Tokens channel, not below MinParallelism
- **updateRTO(rtt)**: Exponential smoothing `newSRTT = (srtt*7 + rtt)/8`, `newRTO = newSRTT*3`, clamped to [50ms, MaxRTTTimeout]

### 3.4 Packet Sending

`BuildIntoBuffer()` obtains a 128-byte buffer from `sync.Pool` and constructs the complete Ethernet/IP/TCP (or UDP, ICMP) packet.

**Channel ID encoding**: The channel ID is encoded into the TCP/UDP source port:
```
srcPort = BASE_PORT + channelID
```
On receive, `channelID` is decoded directly from the reply's destination port, achieving O(1) probe matching.

### 3.5 Packet Reception (RunDispatcher)

RunDispatcher runs the following flow in a background loop:

1. Calls `pcapHandle.ZeroCopyReadPacketData()` for zero-copy packet reading
2. Validates: EtherType must be 0x0800 (IPv4), length ≥ 34, IP header must be complete
3. Extracts IP protocol (packetData[23]), dispatches by protocol type:
   - TCP/UDP: Decode channelID from transport header (destination port), extract srcIP and srcPort
   - ICMP: Call decodeICMPMatch() to parse the embedded original IP packet inside ICMP error messages, extract channelID, srcIP, srcPort
   - Other protocols: Skip
4. Constructs checksum `(srcIP << 16) | srcPort`, atomically compares against expected value in Targets[channelID]; drops on mismatch
5. Calls ExtractTensor() to collapse IPv4 and transport headers into 32-bit PacketTensor
6. Non-blocking write to `e.Channels[channelID]`; if channel full, increments MetricDispatchDrops

### 3.6 L7 Service Detection (RunL7Dispatcher)

Two modes:

**Passthrough mode (no -V)**: Passes L4 results through directly, marking `service=""`.

**Full service detection mode (-V)**:
- Consumes L4 open results from GlobalResultBuffer
- 1000 worker goroutines take tasks from l7TaskQueue
- Each task selects candidate nmap probes via port index
- Establishes TCP connection → sends probe → accumulates response
- Pre-compiled regex matching extracts service/product/version/info/hostname/os/device/cpes
- Results written back to GlobalResultBuffer

**nmap-service-probes integration**:
- Parses nmap-service-probes file at startup
- Extracts all Probes (probe strings), Matches (regex + service info), ports/sslports/fallback directives
- Builds port→probes index, sorted by rarity
- All regex pre-compiled, zero runtime overhead

### 3.7 UAM Hook (uam_hook.go)

Asynchronous UAM SQLite writes during scanning:

- **Event queue**: 65536-capacity channel
- **GSIngester**: Background goroutine consuming events, writing to SQLite
  - `IngestResult()`: L4 scan results → Observation + Claims + Projection refresh
  - `IngestServiceResult()`: L7 results → additional Claims (does not override L4 port state)
  - `IngestDiscovery()`: Host discovery → reachability marking
- **PersistDone**: Completion signal channel ensuring main flow waits for all UAM writes

### 3.8 Result Portrait (report.go)

After scanning, all facts are aggregated into a `PortraitReport`:

```json
{
  "command": "goscan scan 192.168.1.10 --syn -V",
  "targets": ["192.168.1.10"],
  "profiles": ["tcp-syn"],
  "ports": [22, 80, 443],
  "hosts": [{
    "ip": "192.168.1.10",
    "endpoints": [{
      "port": 443, "protocol": "tcp",
      "summary_state": "open",
      "facts": {"tcp-syn": "open"},
      "service": "https", "product": "nginx",
      "version": "1.24.0", "banner": "HTTP/1.1 200 OK..."
    }]
  }]
}
```

`summary_state` is derived from fact aggregation: consensus when methods agree, `indeterminate` when they conflict.

---

## 4. gping Probe Engine

### 4.1 Design Positioning

gping is not a GS continuation or post-processor, but an independent multi-route probe engine:

1. **Independent tool**: Can probe IPs/URLs directly without UAM dependency
2. **UAM verifier**: Reads UAM asset context, performs verification, writes conclusions back

### 4.2 Unified Lifecycle

All actions share the same lifecycle:

```
Resolve → Plan → Prepare → Execute → Interpret → Emit
```

- **Resolve**: Parse target source (URL / literal IP / UAM endpoint / UAM query)
- **Plan**: Build ActionUnit list (template expansion or CLI parameters)
- **Prepare**: Build concrete execution parameters (preparedRun)
- **Execute**: Route to Raw / Stack / App executor
- **Interpret**: Convert execution evidence to standardized Claims
- **Emit**: Terminal output / JSON / UAM writeback

### 4.3 Three-Route Executors

#### Raw Route (raw.go)

Bypasses the OS protocol stack, directly constructing and sending raw packets.

**TCP probing (executeRawTCP)**:
- Constructs Ethernet / IP / TCP layers via gopacket
- Supports custom TCP Flags, TTL, Window Size, data length
- Opens pcap handle + BPF filter to only receive relevant replies
- `rawTCPFlags` struct provides complete TCP flag parsing
- Supports strict mode (strict execution) and probe mode (experimental probing)

**ICMP probing (executeRawICMP)**:
- Constructs Ethernet / IP / ICMP Echo Request
- Receives Echo Reply or ICMP errors
- Determines host reachability

**Special features**:
- `corruptTransportChecksum()`: Send malformed checksum packets (badsum testing)
- `openRawHandle()`: pcap open with BPF filter
- Complete timeout and retry mechanism

#### Stack Route (stack.go)

Uses OS protocol stack for real communication.

**TCP Connect (executeTCPConnect)**:
- Standard `net.DialTimeout` TCP connection
- Error classification: ECONNREFUSED → closed, timeout → filtered, success → open

**TLS Handshake (executeTLSHandshake)**:
- TCP connection + TLS ClientHello
- Extracts server certificate info: Subject, Issuer, SANs, ALPN, TLS version
- Custom TLS Config supporting skip verification

**Banner Read (executeBannerRead)**:
- TCP connection + SetReadDeadline
- Reads initial banner bytes, parses product/version

#### App Route (app.go + 7 adapters)

Application-layer protocol adapters, unified via `AppAdapter` interface:

```go
type AppAdapter interface {
    Name() string
    Capabilities() AdapterCapabilities
    Execute(ctx context.Context, req AppRequest) (AppResult, error)
}
```

| Adapter | File | Supported Methods |
|---------|------|-------------------|
| HTTP | app_adapter_http.go | http-head, http-get, http-post |
| DNS | app_adapter_dns.go | dns-query (A/NS/CNAME/TXT/AAAA) |
| SSH | app_adapter_ssh.go | ssh-banner, ssh-kexinit, ssh-hostkey |
| MySQL | app_adapter_mysql.go | mysql-greeting, mysql-capabilities, mysql-starttls |
| Redis | app_adapter_redis.go | redis-ping, redis-info-server, redis-info-replication |
| FTP | app_adapter_ftp.go | ftp-banner, ftp-feat, ftp-auth-tls |
| SMTP | app_adapter_smtp.go | smtp-banner, smtp-ehlo, smtp-starttls |

**Adapter highlights**:
- SSH: Full binary SSH protocol + ECDH key exchange + SHA256 host key fingerprint
- MySQL: Protocol version parsing + Server Version + Capability Flags + MariaDB/Percona flavor detection
- Redis: RESP protocol implementation + INFO parsing + auth detection
- DNS: UDP/TCP dual transport + complete DNS wire format encode/decode
- SMTP: STARTTLS upgrade + TLS certificate extraction
- FTP: RFC 959 multi-line reply parsing + AUTH TLS

### 4.4 Template System

16 built-in YAML templates with variable expansion (`${var}`), conditional execution (`when` DSL), extraction rules, and recommendation rules. Templates are organized as:

```
templates/
├── raw/basic-syn-check.yaml        # TCP SYN basic check
├── stack/basic-banner-read.yaml    # Banner read
├── http/reverse-proxy-confirm.yaml # HTTP reverse proxy confirmation
├── dns/basic-confirm.yaml          # DNS basic confirmation
├── ftp/basic-confirm.yaml          # FTP basic confirmation
├── smtp/basic-confirm.yaml         # SMTP basic confirmation
├── ssh/basic-confirm.yaml          # SSH basic confirmation
├── redis/basic-confirm.yaml        # Redis basic confirmation
├── mysql/basic-confirm.yaml        # MySQL basic confirmation
├── uam/https-enrich.yaml           # HTTPS asset enrichment
├── uam/dns-enrich.yaml             # DNS asset enrichment
├── uam/ftp-enrich.yaml             # FTP asset enrichment
├── uam/smtp-enrich.yaml            # SMTP asset enrichment
├── uam/ssh-enrich.yaml             # SSH asset enrichment
├── uam/redis-enrich.yaml           # Redis asset enrichment
└── uam/mysql-enrich.yaml           # MySQL asset enrichment
```

### 4.5 Interpreter (interpret.go)

`buildClaimsFromEvidence()` converts execution evidence to UAM Claims, supporting 24+ methods each with specific claim generation logic covering TCP port states, ICMP reachability, TLS certificates, HTTP headers, DNS results, SSH host keys, MySQL versions, Redis roles, FTP/SMTP banners, and more.

### 4.6 Target Resolver (resolver.go)

Four target sources:

1. **URL parsing**: `https://1.2.3.4/path` → TargetContext{IP, Port, Scheme, Path, SNI}
2. **Literal target**: `--ip 1.2.3.4 --port 443` → direct construction
3. **UAM endpoint ID**: `--uam-endpoint <id>` → SQLite query
4. **UAM filtered query**: `--uam-service https --pick-index 1` → query endpoint list + index selection

Supports `tryHydrateFromUAM()` for enriching context (service/product/verification_state).

### 4.7 Auxiliary Features

- **candidates**: List UAM endpoints matching filter criteria, each with auto-recommended templates
- **preview**: Complete Resolve → Plan, output action list without execution
- **history**: Query gping execution history with observation and endpoint state changes
- **suggestions**: Heuristic template recommendations based on port/protocol/service/product

---

## 5. UAM Unified Asset Model

### 5.1 Five-Layer Object Model

**Layer 1 — Identity**:
- Host: Host identity, currently identified by IP (host_id = 'host:' + ip)
- Endpoint: Endpoint identity, composite key of IP + Protocol + Port
- Identity objects are append-only, recording first/last seen timestamps

**Layer 2 — Observation**:
- Records what a specific tool saw at a specific time as raw facts
- Sources: GS scan results, gping action evidence, Module specialized results
- Observations are append-only, immutable, preserving complete data_json

**Layer 3 — Claim**:
- Normalizes Observations into unified asset assertions
- Port states: open / closed / filtered / unfiltered
- Service identification: service / product / version / info / hostname / os / device / cpes
- Host reachability: reachable / unreachable
- Manual verification state: none / pending / confirmed / overridden
- Claims can be superseded by higher-priority subsequent claims

**Layer 4 — Projection**:
- Current best-view derived from Claims, similar to materialized views
- HostProjectionCurrent: Host-level current state (reachability, etc.)
- EndpointProjectionCurrent: Endpoint-level current state (port state, service info, verification state, etc.)
- Incrementally refreshed on each new Claim, not recomputed from scratch

**Layer 5 — Extension**:
- ModuleResult: Attachment point for specialized scan deep results
- Module-specific fields go here without polluting the core asset model
- Flexible structure via module_name / result_type / result_json

### 5.2 Claim Priority System

```go
const (
    PriorityInferred  = 1  // Program inference
    PriorityObserved  = 2  // Tool observation (GS/gping automatic)
    PriorityManual    = 3  // Manual confirmation (gping --assert confirmed)
    PriorityOverride  = 4  // Manual override (gping --assert overridden)
)
```

Projection refresh rules:
- When multiple Claims compete for the same field, higher priority wins
- Same priority: newer timestamp wins
- `override` and `manual` priority Claims are never overwritten by subsequent automatic scan results

### 5.3 SQLite Schema (8 tables, 10+ indexes, 3 views)

Core tables: **runs** (tool run records), **hosts** (host identity), **endpoints** (endpoint identity), **observations** (raw observations), **claims** (normalized assertions), **host_projection_current** (host current projection), **endpoint_projection_current** (endpoint current projection), **module_results** (extension results).

Views: **v_endpoint_assets**, **v_host_assets**, **v_recent_observations** — join views for convenient querying.

### 5.4 Storage Layer (store/sqlite/)

**Initialization**:
- `Open(path)`: Open/create SQLite database, enable WAL mode, foreign keys, busy timeout
- `OpenExisting(path)`: Open existing database only
- `Migrate()`: Idempotent table creation (CREATE TABLE IF NOT EXISTS)

**ID generation** (ids.go): Format `{prefix}_{timestamp}_{hex}` with millisecond Unix timestamps and crypto/rand 4-byte random hex.

**CRUD operations**: ENSure semantics for Host/Endpoint (INSERT OR IGNORE + UPDATE last_seen_at), transactional Observation + Claims insertion, UPSERT semantics for projections.

### 5.5 Normalization Layer (normalize/)

- **gs.go**: Converts GS scan results to UAM objects — Observation, port state/reachability/service Claims
- **gping.go**: Converts gping execution evidence to UAM Claims from standardized GPingClaimInput
- **module.go**: Module result normalization, reusing gping Claim generation logic

### 5.6 Projection Engine (project/projection.go)

```go
func ClaimPriority(c Claim) int { ... }
func ShouldApply(newClaim, currentClaim) bool { ... }
func ApplyHostProjection(proj *HostProjectionCurrent, claim Claim) { ... }
func ApplyEndpointProjection(proj *EndpointProjectionCurrent, claim Claim) { ... }
```

Refresh flow (refreshProjections()): Load current projection → Query relevant Claims (sorted by priority + time) → Check ShouldApply() for each → Apply qualifying Claims → Save updated projection.

### 5.7 Ingestion Services (service/)

- **GSIngester** (ingest_gs.go): Creates Run, ingests L4 results + L7 service supplements + host discovery
- **GPingIngester** (ingest_gping.go): Creates Run, ingests gping observations
- **ModuleIngester** (ingest_module.go): Creates Run, ingests Module observations + ModuleResults in transaction

### 5.8 Query & Report Services

**QueryService** provides read-only query methods with multi-condition AND filtering: ListRunsFiltered, ListHostsFiltered, ListEndpointsFiltered, ListObservationsFiltered.

**ReportService**: BuildHostReport() aggregates host + all endpoints + all observations + associated runs. RenderHostReport() generates human-readable text reports.

---

## 6. CLI Command Reference

### 6.1 Main Command

```bash
goscan [command]
```

### 6.2 scan — GS Scan Command

```bash
goscan scan <targets> [flags]
```

**Scan techniques**: `--syn/-s` (TCP SYN, default), `--ack/-A` (TCP ACK), `--window/-W` (TCP Window), `--udp/-U` (UDP)

**Ports & targets**: `-p/--port` (specify ports), `-F/--fast` (Top 100 ports), `--top-ports <n>`, `--exclude`, `--randomize-hosts`

**Service & output**: `-V/--service` (enable L7), `-o/--output` (portrait file), `--output-format` (json/yaml), `--uam-db` (UAM SQLite path)

**Performance**: `-T/--timing` (0-5, default 3), `--min-rate/--max-rate` (pps), `--min-parallelism/--max-parallelism`, `--max-retries`, `--max-rtt-timeout` (ms), `--host-timeout` (ms)

### 6.3 gping — Probe Command

```bash
goscan gping [flags]              # Execute probe
goscan gping templates [flags]    # List/view templates
goscan gping candidates [flags]   # List UAM candidates
goscan gping preview [flags]      # Preview actions
goscan gping history [flags]      # View execution history
```

**Target selection** (at least one required): `--ip`, `--url`, `--uam-endpoint`, `--uam-db` + filter conditions

**UAM filters**: `--uam-service`, `--uam-port`, `--uam-protocol`, `--pick-index`, `--pick-first`

**Execution control**: `--method`, `--route` (raw/stack/app), `--template`, `--assert` (none/confirmed/overridden), `--port`, `--raw-flags`

### 6.4 uam — Asset Query Command

```bash
goscan uam runs --db <path> [flags]           # Run records
goscan uam hosts --db <path> [flags]          # Host list
goscan uam endpoints --db <path> [flags]      # Endpoint list
goscan uam observations --db <path> [flags]   # Observation history
goscan uam report --db <path> [flags]         # Comprehensive report
```

All subcommands share filter flags: `--ip`, `--port`, `--protocol`, `--tool`, `--run-id`, etc.

---

## 7. Data Flows & Lifecycles

### 7.1 GS Scan Complete Data Flow

**Phase 1 — Task Generation**: IP iterator (single IP, CIDR, range) combined with port list and scan profiles (tcp-syn/tcp-ack/tcp-window/udp) → TaskGenerator produces EmissionTask batches (exactly 8 bytes each).

**Phase 2 — L4 Probing**: Engine.Run() main loop consumes task batches. Each task passes CWND concurrency control (acquire Token), Channel ID allocation (acquire FreeID), rate control (acquire sendToken), then goroutine launches LaunchProbe:
- BuildIntoBuffer() constructs Ethernet/IP/TCP packet on pooled memory
- pcap.WritePacketData() sends from NIC
- select waits for reply (channels[id]) or timeout (timer)
- Successful replies collapsed to PacketTensor via ExtractTensor()
- evaluateTaskResult() maps tensor to port state
- Result written to GlobalResultBuffer via emitScanResult()
- If --uam-db specified, also pushed to GSIngester via uam_hook

RunDispatcher() continuously receives: pcap zero-copy read → validation → Channel ID decode → target verification → tensor collapse → write to goroutine's channels[id].

**Phase 3 — L7 Service Detection**: RunL7Dispatcher() consumes L4 open results. Without -V: passthrough with service="". With -V: 1000 workers → port-indexed nmap probe selection → TCP connect → send probe → accumulate response → pre-compiled regex matching → write back.

**Phase 4 — Portrait Output**: report.go aggregates all facts by Host → Endpoint, computes summary_state, exports PortraitReport as JSON or YAML.

### 7.2 UAM Write Path

Write entry points: scan via uam_hook.go event queue (async), gping via ingest_gping.go (sync), module via ingest_module.go (sync).

Write flow (contractIngester base class):
1. BeginTx() opens SQLite transaction
2. Ensure Host and Endpoint identity records exist (INSERT OR IGNORE)
3. InsertObservation() writes raw observation
4. InsertClaims() writes normalized assertions (may be multiple)
5. InsertModuleResult() for module-specific data if present
6. Commit() commits transaction
7. refreshProjections() incrementally refreshes affected projection fields

### 7.3 gping Execution Lifecycle

Six-phase lifecycle for all execution paths:

1. **Resolve**: Route to URL parser / literal constructor / UAM endpoint query / UAM filter query; optionally hydrateFromUAM
2. **Plan**: Template expansion (${var} with base + defaults + CLI overrides, when condition evaluation) or CLI parameter action construction
3. **Prepare**: Build preparedRun context
4. **Execute**: Route dispatch to raw (TCP/ICMP) / stack (connect/TLS/banner) / app (7 adapters)
5. **Interpret**: Map execution evidence to standardized UAM Claims
6. **Emit**: Terminal output / JSON result / UAM writeback with operator assertions

---

## 8. Package Structure & Source Navigation

### 8.1 Suggested Reading Order

**Getting started** (understand entry point and scan flow):
1. `main.go` — Program entry
2. `cmd/root.go` — CLI commands
3. `pkg/core/engine.go` — L4 engine core
4. `pkg/core/task.go` — Task data structures
5. `pkg/core/tensor.go` — PacketTensor classification

**Deep dive** (L7 and UAM):
6. `pkg/core/l7engine.go` — L7 engine
7. `pkg/l7/nmap_parser.go` — nmap probe parsing
8. `pkg/core/uam_hook.go` — UAM hook
9. `pkg/core/report.go` — Portrait generation
10. `internal/uam/domain/types.go` — UAM domain definitions

**gping** (probe engine):
11. `internal/gping/runner.go` — gping main loop
12. `internal/gping/resolver.go` — Target resolution
13. `internal/gping/planner.go` — Action planning
14. `internal/gping/raw.go` — Raw packet sending
15. `internal/gping/interpret.go` — Evidence interpretation

**UAM depth**:
16. `internal/uam/store/sqlite/schema.go` — Complete DDL
17. `internal/uam/store/sqlite/store.go` — Storage layer
18. `internal/uam/project/projection.go` — Projection engine
19. `internal/uam/service/ingest_gs.go` — GS ingestion
20. `internal/uam/service/query.go` — Query service

### 8.2 Complete File Index

**cmd/** (3 files): root.go, gping.go, uam.go

**pkg/core/** (17 files): engine.go, l7engine.go, dispatcher.go, channel_port.go, pcap_handle.go, task.go, task_generator.go, targets.go, tensor.go, scan_result.go, scan_profile.go, report.go, reporter.go, metrics.go, performance.go, portmap.go, run_metadata.go, injector.go, uam_hook.go

**pkg/l7/** (3 files): nmap_parser.go, l7worker.go, fingerprint.go

**internal/gping/** (25 files): runner.go, types.go, execute.go, raw.go, stack.go, app.go, app_adapter.go, app_adapter_http.go, app_adapter_dns.go, app_adapter_ssh.go, app_adapter_mysql.go, app_adapter_redis.go, app_adapter_ftp.go, app_adapter_smtp.go, planner.go, resolver.go, preview.go, interpret.go, templates.go, template_execution.go, template_helpers.go, candidates.go, suggestions.go, catalog.go, history.go, helpers.go, protocols.go, dsl_types.go

**internal/uam/** (15 files): domain/types.go, normalize/{gs,gping,module}.go, project/projection.go, service/{common,ingest_gs,ingest_gping,ingest_module,query,report,helpers}.go, store/sqlite/{store,schema,ids}.go

---

## 9. Key Design Decisions

### 9.1 Why Not Use connect() as the Primary Scan Path?

The OS `connect()` triggers the full TCP state machine — the kernel handles retransmission, maintains connection state, and limits concurrent connections. For mass-scale port scanning, these behaviors severely constrain throughput and controllability. Going_Scan directly constructs raw packets + pcap receive, maintaining full control over send cadence, retry strategy, and concurrency window.

### 9.2 Why PacketTensor Instead of Full Protocol Parsing?

Full layered protocol parsing (Ethernet → IP → TCP → Application) is a performance bottleneck in high-speed receive scenarios. PacketTensor encodes key features (protocol, flags, TTL, window size) in 32 bits; all state classification is done via O(1) bitwise operations — zero allocation, zero branch prediction misses.

### 9.3 Why Separate Observation and Claim in UAM?

Observation records "at what time, with what tool, what was seen" — this is raw fact. Claim records "what asset assertion does this imply" — this is normalized conclusion.

Separation purpose:
- One Observation can produce multiple Claims
- Observations from different tools can produce semantically unified Claims
- Claims can be superseded by higher-priority subsequent observations
- Observations are forever immutable (append-only); Claims can be superseded

### 9.4 Why a Projection Layer in UAM?

Without Projection, every query for "what is the current port state" would require scanning all Claims and recomputing. Projection is a materialized view, always reflecting the current best state. When a new Claim is written, only affected projection fields are refreshed — not a full recomputation.

### 9.5 Why Three Routes in gping?

- **Raw**: Bypasses protocol stack, precisely controls every packet field (TTL, Flags, Window, checksum) — suited for firewall testing and malformed packet experiments
- **Stack**: Uses OS protocol stack for real communication behavior — suited for confirming whether a service is truly reachable
- **App**: Application-layer semantics — suited for confirming "this port really runs HTTPS, and here's the certificate"

The three routes solve problems at different layers and are not interchangeable.

---

## 10. Build & Test

### Build

```bash
go build -o goscan .
```

### Run Tests

```bash
go test ./...
```

### Dependencies

| Dependency | Purpose |
|------------|---------|
| `github.com/google/gopacket` | Raw packet construction & pcap receive |
| `github.com/mattn/go-sqlite3` | SQLite driver (CGO) |
| `github.com/spf13/cobra` | CLI command framework |
| `github.com/stretchr/testify` | Test assertions |
| `gopkg.in/yaml.v3` | YAML parsing (templates + portrait export) |
| `github.com/jackpal/gateway` | Default gateway discovery |
| `golang.org/x/sys` | System calls (syscall constants) |
| `golang.org/x/net` | Network extensions |

### Runtime Requirements

- Go 1.24+ toolchain
- libpcap (Linux) / npcap (Windows) or equivalent pcap library
- Raw packet privileges (Linux: `CAP_NET_RAW` or root; macOS: root)
- Optional: SQLite development libraries (needed for CGO compilation)

---

> This document is based on Going_Scan V2 Engine, last updated 2026-05-04.
