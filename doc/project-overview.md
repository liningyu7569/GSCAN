# Going_Scan — Project Overview

## One-Line Definition

Going_Scan is a **high-performance network asset scanning and analysis platform written in Go**, composed of three cooperating subsystems (GS for high-speed discovery, gping for targeted validation, UAM for unified asset modeling) that together form a complete "discover, persist, verify, extend" asset reconnaissance workflow.

---

## What Problem Does This Solve?

Traditional scanners force a trade-off: prioritize throughput by compressing results to "port open or not," or prioritize depth by spending excessive time on per-connection probing.

Going_Scan separates and connects these concerns:

- **L4 Layer** — High-speed, stateless, controlled raw probing for rapid discovery
- **L7 Layer** — Consumes only trusted results for service identification and fingerprinting
- **Output Layer** — Aggregates fact streams into structured host/port portraits
- **Asset Layer (UAM)** — Persists all discoveries as traceable asset knowledge
- **Verification Layer (gping)** — Targeted confirmation of suspicious endpoints, writing back to the asset store

The goal is not "a better scanner" — it's **a traceable, verifiable, extensible asset intelligence system**.

---

## Three-Tool Collaboration Architecture

### How They Work Together

The three tools form a clear asset processing pipeline:

1. **GS (High-speed Discovery)** — Mass-scale L4 port scanning + L7 service identification, producing initial asset facts (hosts, ports, services) and writing them into UAM as Observations and Claims
2. **UAM (Asset Hub)** — Receives GS discoveries, manages asset identity (Host/Endpoint), stores raw observations, normalizes claims, and maintains current best-view projections, with a query interface
3. **gping (Targeted Validation)** — Reads asset context from UAM, performs precise verification on targets (supporting Raw/Stack/App three routes), and writes verification conclusions back to UAM Claims and Projections

All three tools share a single SQLite database (uam.db) as their data exchange hub.

### Division of Responsibility

| Tool | Role | Core Mission |
|------|------|-------------|
| **GS** | High-speed Discovery Frontend | Mass-scale, high-throughput automated asset discovery |
| **UAM** | State Backend | Unified identity, observation, claim, projection, and extension management |
| **gping** | Targeted Validator | Human-driven precise verification, correction, and override |

GS casts a wide net, gping confirms with precision, and UAM keeps the long-term record. The three have clear, non-overlapping responsibilities.

---

## Core Technical Highlights

### 1. PacketTensor — Extreme Compression Classification

Inbound replies are compressed into a **32-bit lightweight state tensor** (`uint32`) with O(1) bitwise port state classification, producing zero GC pressure — the performance cornerstone of the L4 engine.

Bit layout:

- Bits 0-7: TCP Flags / ICMP Type
- Bits 8-15: IP TTL
- Bits 16-19: Window Size (quantized) / ICMP Code
- Bits 20-27: IP Protocol
- Special value 0xFFFFFFFF: Timeout sentinel

### 2. CWND Adaptive Concurrency Control

Modeled after TCP congestion control: the concurrency window grows on successful replies and multiplicatively halves on timeouts. Engine parallelism self-tunes to network conditions, complemented by SRTT exponential smoothing and dynamic RTO computation — forming a complete adaptive control loop.

### 3. Channel ID Physical Matching

The channel ID is encoded into the source port of each outgoing packet. On receive, the destination port directly (O(1)) locates the corresponding probe with no table lookups. A 64-bit checksum (srcIP + srcPort) ensures atomic matching of replies to originating probes.

### 4. Zero-Allocation Send Pipeline

128-byte packet buffers are pooled via `sync.Pool`. L2/L3/L4 headers are built directly on pooled memory. A lock-free ring buffer (capacity 65536) carries high-throughput result streams between pipeline stages.

### 5. Five-Layer UAM Asset Model

UAM uses a strict layered design where each layer has non-overlapping responsibilities:

- **Layer 1 — Identity**: Host (keyed by IP) and Endpoint (keyed by IP + Protocol + Port)
- **Layer 2 — Observation**: Raw observation records — "which tool, at what time, saw what"
- **Layer 3 — Claim**: Normalized assertions — "what asset conclusion does this observation imply" (port state, service identity, reachability)
- **Layer 4 — Projection**: Current best-view derived from Claims (HostProjectionCurrent / EndpointProjectionCurrent)
- **Layer 5 — Extension**: Deep scan results stored in ModuleResult without polluting the core asset model

Key design principles:
- **Observation ≠ Claim**: Observations record "what happened"; Claims record "what this means"
- **Projection ≠ History**: The current view is derived from Claims, not a direct overwrite of the last Observation
- **Claim Priority System**: override(4) > manual(3) > observed(2) > inferred(1), ensuring manual confirmation is never overwritten by automated scans

### 6. gping Three-Route Unified Verification

gping is not a GS accessory but an independent multi-route probe engine. The three routes have completely different internal implementations but share a unified lifecycle: Resolve → Plan → Prepare → Execute → Interpret → Emit.

| Route | Purpose | Typical Methods |
|-------|---------|----------------|
| **Raw** | Packet-level control bypassing the OS stack | tcp-syn, icmp-echo-raw |
| **Stack** | Real communication via OS protocol stack | tcp-connect, tls-handshake, banner-read |
| **App** | Application-layer protocol adapters | HTTP/DNS/SSH/MySQL/Redis/FTP/SMTP |

### 7. Template-Based Verification Workflows

gping includes 16 built-in YAML templates supporting `${var}` variable expansion, conditional execution (`when` DSL), multi-step orchestration, extraction rules (`extracts`), and recommendation rules (`recommend`), standardizing common verification workflows. A single command can complete the full confirmation flow: "TCP connect + TLS handshake + HTTP request + write results to UAM."

---

## Supported Scan Capabilities

### L4 Scan Modes
- **TCP SYN** — Half-open scan (default), the most common port scanning technique
- **TCP ACK** — Firewall rule discovery, determines whether ports are filtered
- **TCP Window** — Uses TCP Window field to assist port state classification
- **UDP** — UDP port state probing
- **Host Discovery** — Multi-protocol liveness detection (ICMP Echo / TCP / UDP), results stream into port scanning in real time

### L7 Service Detection
- Embedded nmap-service-probes database
- Pre-compiled regex matching with port-indexed probe selection
- Extracted fields: service, product, version, info, hostname, os, device, cpes
- Supports TCP/UDP, SSL ports, fallback probes, rarity classification

### gping Application-Layer Adapters
HTTP(S), DNS, SSH (with ECDH key exchange + SHA256 host key fingerprinting), MySQL (including MariaDB/Percona flavor detection), Redis (RESP protocol + INFO parsing), FTP (RFC 959 multi-line replies), SMTP (with STARTTLS certificate extraction)

---

## Typical Workflows

### Basic: Quick Scan

```bash
./goscan scan 192.168.1.0/24 --syn -F -V -o report.json
```

Perform a fast SYN scan with service detection on a /24 subnet, export results as a JSON portrait.

### Complete: GS + UAM + gping Asset Loop

**Step 1** — GS discovers assets and persists to UAM:

```bash
./goscan scan 192.168.1.0/24 --syn -V --uam-db uam.db
```

**Step 2** — Identify suspicious HTTPS endpoints:

```bash
./goscan gping candidates --uam-db uam.db --uam-service https
```

**Step 3** — Verify and confirm:

```bash
./goscan gping --uam-db uam.db --uam-service https --pick-index 1 \
  --template uam/https-enrich --assert confirmed
```

**Step 4** — View a host's complete asset report:

```bash
./goscan uam report --db uam.db --ip 192.168.1.10
```

---

## Tech Stack & Requirements

- **Language**: Go 1.24+
- **Packet I/O**: libpcap / npcap (requires raw packet send and capture privileges)
- **Storage**: SQLite (WAL mode + foreign key constraints)
- **Privileges**: Root or equivalent capabilities required for scanning on Linux/macOS

---

## Project Status

The GS engine is mature and stable. gping's core routes are implemented (3 routes + 7 protocol adapters + 16 built-in templates). The UAM five-layer model is fully implemented (8 tables + projection engine + query service). The project is currently in a tightening and polishing phase, with future directions including specialized protocol deep-scanning and template ecosystem expansion.
