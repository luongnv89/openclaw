# OpenClaw Security & Optimization Review

**Date:** 2026-02-12
**Scope:** Full codebase analysis — security vulnerabilities, performance optimization, credential handling, channel security, input validation

## Overall Assessment: Strong foundation, specific gaps to address

The codebase demonstrates mature security engineering with defense-in-depth principles. Key strengths include timing-safe auth, SSRF protection with DNS pinning, comprehensive log redaction, sandboxed command execution, and parameterized SQL queries. However, several areas need attention.

---

## Table of Contents

1. [Security Findings by Severity](#1-security-findings-by-severity)
   - [Critical](#critical)
   - [High](#high)
   - [Medium](#medium)
2. [Performance & Optimization Findings](#2-performance--optimization-findings)
   - [Memory Management](#memory-management-high-priority)
   - [Async & Resource Cleanup](#async--resource-cleanup-medium-priority)
   - [Build & Startup](#build--startup-low-priority)
3. [Key Security Strengths](#3-key-security-strengths)
4. [Detailed Analysis by Area](#4-detailed-analysis-by-area)
   - [Security Infrastructure](#41-security-infrastructure)
   - [Input Validation & Injection](#42-input-validation--injection)
   - [Secrets & Credential Handling](#43-secrets--credential-handling)
   - [Channel Security](#44-channel-security)
   - [Plugin Security](#45-plugin-security)
   - [WebSocket Security](#46-websocket-security)
5. [Design Decisions Not to Change](#5-design-decisions-not-to-change)
6. [Recommended Priority Actions](#6-recommended-priority-actions)
7. [Essential Files for Security Review](#7-essential-files-for-security-review)

---

## 1. Security Findings by Severity

### Critical

| #   | Finding                                | Location                                                                                                            | Risk                                                              | Status                                                                                                                                                                |
| --- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1  | **No plugin sandboxing**               | `src/plugins/loader.ts` — plugins loaded via `jiti` with full Node.js access                                        | Malicious plugin can exfiltrate all secrets, tokens, messages     | **Mitigated** — non-bundled plugins get security warning, redacted config (no auth/tokens), restricted runtime (no command exec/config write), sandboxed tool context |
| C2  | **SSRF redirect bypass**               | `src/infra/net/fetch-guard.ts:149-159` — redirect targets not re-validated for private IPs                          | Initial URL passes SSRF check, then redirects to `127.0.0.1`      | **Fixed** — redirect targets validated against private IPs, blocked hostnames, and non-HTTP protocols before following                                                |
| C3  | **OAuth tokens stored in plaintext**   | `src/agents/auth-profiles/store.ts:368-378` — `saveJsonFile()` writes tokens as plaintext JSON                      | Filesystem access (malware, backup leak) compromises all API keys | **Fixed** — AES-256-GCM encryption at rest with master key via macOS Keychain or file-based key; transparent migration for existing stores                            |
| C4  | **Prompt injection is detection-only** | `src/security/external-content.ts:33-41` — `detectSuspiciousPatterns()` returns matches but content still processed | No blocking mechanism for high-confidence injection attempts      | **Fixed** — confidence-tiered pattern detection (high/medium/low) with `blockOnSuspicious` config to block high-confidence injection attempts                         |

### High

| #   | Finding                                             | Location                                                                                        | Risk                                                                                                       |
| --- | --------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| H1  | **Telegram webhook secret optional**                | `src/telegram/webhook.ts:46-48` — `secretToken: opts.secret` can be `undefined`                 | Webhook endpoint accessible without signature verification                                                 |
| H2  | **Slack signing secret can be empty**               | `src/slack/monitor/provider.ts:125` — `signingSecret: signingSecret ?? ""`                      | Empty string may bypass HMAC verification                                                                  |
| H3  | **No WebSocket rate limiting**                      | `src/gateway/` — no per-IP connection limits or message rate limiting                           | Connection flood / DoS vulnerability                                                                       |
| H4  | **Token refresh errors may leak tokens**            | `src/agents/auth-profiles/oauth.ts:271-283` — error includes `buildOAuthApiKey()` result        | Logs/crash reports could contain full tokens                                                               |
| H5  | **Device auth v1 has no nonce**                     | `src/gateway/device-auth.ts:14` — v1 still supported without nonce                              | v1 tokens can be replayed if intercepted                                                                   |
| H6  | **Cloud metadata blocklist incomplete**             | `src/infra/net/ssrf.ts:26` — only `metadata.google.internal` blocked                            | Missing AWS (`169.254.169.254`), Azure, Alibaba metadata endpoints                                         |
| H7  | **Skill scanner has limited pattern coverage**      | `src/security/skill-scanner.ts:79-137` — only 4 line rules + 4 source rules                     | Missing: `rm -rf`, private IP network access, dynamic imports, dangerous Node.js modules (`vm`, `cluster`) |
| H8  | **TLS certificates have no rotation mechanism**     | `src/infra/tls/gateway.ts:67-150` — cert valid for 10 years, no auto-renewal or expiry warnings | Gateway breaks without warning after expiry                                                                |
| H9  | **Pairing store allows unlimited pending requests** | `src/pairing/pairing-store.ts:15` — `PAIRING_PENDING_MAX = 3` not enforced at all API levels    | Attacker floods pairing endpoint                                                                           |
| H10 | **No token revocation command**                     | N/A (missing feature)                                                                           | No quick way to invalidate compromised tokens                                                              |

### Medium

| #   | Finding                                             | Location                                                                                     | Risk                                                      |
| --- | --------------------------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| M1  | **Unicode confusables bypass**                      | `src/security/external-content.ts:89-150` — only fullwidth range sanitized                   | Other unicode lookalikes can bypass marker filtering      |
| M2  | **Origin check allows any loopback port**           | `src/gateway/origin-check.ts:65-68` — no port matching for loopback                          | Malicious local process can connect from any local port   |
| M3  | **TLS auto-gen certs have no SAN**                  | `src/infra/tls/gateway.ts:58` — CN=openclaw-gateway, no Subject Alternative Name             | Encourages users to disable cert validation               |
| M4  | **Config file can contain plaintext secrets**       | `src/security/audit-extra.sync.ts:336-363` — only warns, doesn't prevent                     | Users may ignore warnings, leave secrets on disk          |
| M5  | **No file locking for device auth store**           | `src/infra/device-auth-store.ts:61-68` — unlike auth-profiles, no `proper-lockfile`          | Concurrent writes could corrupt JSON                      |
| M6  | **Race condition in multi-agent token sharing**     | `src/agents/auth-profiles/oauth.ts:248-269` — subagent reads main agent store without lock   | Could copy partially written data                         |
| M7  | **Environment variable substitution not validated** | Config env substitution — `${NONEXISTENT_VAR}` may result in empty string                    | Silent misconfiguration, auth fails with empty tokens     |
| M8  | **Redacted sentinel could collide with user data**  | `src/config/redact-snapshot.ts:9` — `__OPENCLAW_REDACTED__` is plain string                  | Legitimate value redacted by mistake                      |
| M9  | **Audit filesystem checks don't follow symlinks**   | `src/security/audit.ts:143-149` — warns about symlinks but doesn't check target permissions  | Symlink to world-writable directory not fully detected    |
| M10 | **Windows ACL check may miss custom groups**        | `src/security/windows-acl.ts:24-38` — hardcoded trusted/world principal lists                | Custom domain groups not classified                       |
| M11 | **Default channel access policy can be "open"**     | `src/channels/plugins/onboarding/channel-access.ts` — three modes: allowlist, open, disabled | Should default to allowlist, not open                     |
| M12 | **Docker exec command construction**                | `src/agents/bash-tools.shared.ts:80` — `sh -lc ${params.command}`                            | Shell metacharacters possible, though sandboxed in Docker |

---

## 2. Performance & Optimization Findings

### Memory Management (High Priority)

| #   | Finding                              | Location                                                                                       | Impact                                            |
| --- | ------------------------------------ | ---------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| P1  | **Unbounded agent-events maps**      | `src/infra/agent-events.ts:21-23` — `seqByRun`, `runContextById` grow without TTL              | Memory leak in long-running gateway               |
| P2  | **Memory index cache never evicted** | `src/memory/manager.ts:106` — `INDEX_CACHE` holds DB connections indefinitely                  | Each entry holds db connections, watchers, timers |
| P3  | **Chat run registries unbounded**    | `src/gateway/server-chat.ts:42-50` — 4 Maps grow without size limits                           | OOM risk under high traffic                       |
| P4  | **File watcher memory leaks**        | `src/memory/manager.ts:152-156` — multiple watchers/timers; if `close()` not called, they leak | Resource exhaustion over time                     |

### Async & Resource Cleanup (Medium Priority)

| #   | Finding                                             | Location                                                                                                            | Impact                              |
| --- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| P5  | **Debounce timer not cleared before watcher close** | `src/gateway/config-reload.ts:273-377`                                                                              | Dangling timer reference            |
| P6  | **No stuck-process detection**                      | `src/agents/bash-process-registry.ts:70-74` — `runningSessions` grows if processes don't exit                       | Zombie processes accumulate         |
| P7  | **Node registry pending invokes unbounded**         | `src/gateway/node-registry.ts:23-29` — no global timeout or size limit                                              | Queue grows indefinitely under load |
| P8  | **Cron job timeout cleanup**                        | `src/cron/service/timer.ts:213-221` — timeout timer might not be cleared if `executeJobCore` rejects before timeout | Timer leak                          |
| P9  | **Health refresh failures not tracked**             | `src/gateway/server-maintenance.ts:64-72` — failures logged but not counted                                         | Repeated failures go undetected     |

### Build & Startup (Low Priority)

| #   | Finding                                    | Location                                                                           | Impact                                                     |
| --- | ------------------------------------------ | ---------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| P10 | **80+ synchronous imports at startup**     | `src/gateway/server.impl.ts:1-79`                                                  | Slow cold start; many only used conditionally              |
| P11 | **JSON.stringify per client on broadcast** | `src/gateway/server-broadcast.ts:48`                                               | Wasteful — same frame serialized once could be sent to all |
| P12 | **No filtered client sets for broadcast**  | `src/gateway/server-broadcast.ts:68-92` — iterates all clients per broadcast       | O(n) per message with 100+ clients                         |
| P13 | **Config loaded twice during startup**     | `src/gateway/server.impl.ts:170-204` — once for legacy check, once after migration | Unnecessary I/O                                            |

---

## 3. Key Security Strengths

These are well-implemented security measures that should be preserved:

- **Timing-safe token comparison** — `crypto.timingSafeEqual` used consistently (`src/gateway/auth.ts:40-44`, `src/line/signature.ts`)
- **SSRF protection** — DNS pinning, private IP blocking for IPv4 and IPv6, hostname blocklist (`src/infra/net/ssrf.ts`)
- **Comprehensive log redaction** — tokens, PEM blocks, API keys, Bearer headers, provider-specific prefixes (`src/logging/redact.ts:13-36`)
- **File permissions enforced** — 0o600 files, 0o700 dirs for all sensitive files (`src/infra/json-file.ts:16-23`)
- **detect-secrets integration** — `.secrets.baseline` with comprehensive plugin suite
- **Path traversal prevention** — symlink detection, unicode normalization, sandbox escape detection (`src/agents/sandbox-paths.ts`)
- **Environment variable blocking** — LD_PRELOAD, DYLD_INSERT_LIBRARIES, NODE_OPTIONS, PATH, etc. (`src/agents/bash-tools.exec.ts:59-107`)
- **Multi-layer command approval** — ExecSecurity levels: deny, allowlist, full with user confirmation
- **Parameterized SQL everywhere** — prepared statements in all SQLite queries (`src/memory/`)
- **Android encrypted storage** — EncryptedSharedPreferences with AES256-GCM (`apps/android/.../SecurePrefs.kt`)
- **macOS Keychain integration** — credentials stored in system keychain (`src/agents/cli-credentials.ts:247-292`)
- **LINE webhook verification** — exemplary HMAC-SHA256 with timing-safe comparison (`src/line/signature.ts`)
- **Security audit framework** — built-in `openclaw security audit --deep` with 30+ checks (`src/security/audit.ts`)

---

## 4. Detailed Analysis by Area

### 4.1 Security Infrastructure

**Audit System** (`src/security/audit.ts`):

- Comprehensive security auditing with severity levels (info/warn/critical)
- Checks 30+ aspects including filesystem permissions, gateway auth, channel policies, hooks, elevated exec
- Gateway auth validation checks token length, bind mode, Tailscale exposure (lines 258-365)
- Deep channel security analysis for Discord, Slack, Telegram (lines 464-853)

**External Content Protection** (`src/security/external-content.ts`):

- Detects prompt injection patterns with confidence tiers (high/medium/low) at lines 15-56
- `hasHighConfidenceInjection()` identifies clear injection attempts for blocking
- `blockOnSuspicious` config option enables blocking high-confidence injections in cron runner
- Wraps untrusted content with security boundaries at lines 68-86
- Sanitizes marker characters to prevent boundary escaping at lines 111-172
- ~~Gap: detection is passive — matches returned but content still processed (C4)~~ **Fixed**
- Gap: only fullwidth unicode range handled, other confusables not covered (M1)

**Skill Scanner** (`src/security/skill-scanner.ts`):

- Pattern-based code safety rules (exec, eval, crypto-mining, obfuscation) at lines 79-106
- Multi-rule scanning (file read + network = exfiltration warning) at lines 109-137
- Gap: limited to 4 line rules + 4 source rules — missing dangerous patterns (H7)

**Filesystem Security** (`src/security/audit-fs.ts`):

- Cross-platform permission checking (POSIX + Windows ACL) at lines 62-130
- Proper remediation commands for chmod/icacls
- Gap: doesn't follow symlinks to check target permissions (M9)

### 4.2 Input Validation & Injection

**Command Injection — Well Protected:**

- `src/agents/bash-tools.exec.ts` implements multi-layer approval with ExecSecurity levels
- Environment variable blocklists prevent LD_PRELOAD, DYLD_INSERT_LIBRARIES, PATH injection
- Docker sandbox used by default for command execution
- Minor gap: `sh -lc ${params.command}` in Docker exec (M12)

**Path Traversal — Excellent:**

- `src/agents/sandbox-paths.ts` prevents sandbox escapes at lines 33-47
- Recursive symlink detection at lines 89-110
- Unicode space normalization at lines 10-12
- Home directory expansion handled safely

**SQL Injection — No Vulnerabilities Found:**

- All SQLite queries use prepared statements with `?` placeholders
- No string concatenation in query construction
- `src/memory/` subsystem fully parameterized

**SSRF — Strong:**

- Private IP detection covers IPv4 ranges, IPv6 loopback, link-local, ULA
- DNS pinning prevents TOCTOU attacks
- Redirect targets validated against private IPs, blocked hostnames, and non-HTTP protocols
- ~~Gap: redirect targets not re-validated (C2)~~ **Fixed**
- Gap: cloud metadata blocklist incomplete (H6)

**XSS — Low Risk:**

- Application is primarily CLI/API-based, reducing XSS surface
- External content wrapped with security markers
- Markdown rendering through `markdown-it` library

### 4.3 Secrets & Credential Handling

**Storage:**

- File permissions enforced at 0o600/0o700 for all sensitive files
- Auth profiles use file locking (`proper-lockfile`) for concurrent access
- Auth profiles encrypted at rest with AES-256-GCM (`src/agents/auth-profiles/crypto.ts`)
- macOS Keychain integration for CLI credentials and auth store master key
- Android uses EncryptedSharedPreferences with AES256-GCM
- ~~Gap: JSON config files are plaintext — no encryption at rest (C3)~~ **Fixed** for auth profiles
- Gap: other config files are plaintext (M4)
- Gap: device auth store lacks file locking unlike auth-profiles (M5)

**Redaction:**

- Comprehensive log redaction engine (`src/logging/redact.ts`) covering:
  - ENV-style: `API_KEY=...`, `TOKEN=...`, `PASSWORD=...`
  - JSON fields: `"apiKey": "..."`, `"token": "..."`
  - CLI flags: `--api-key ...`
  - Authorization headers: `Bearer ...`
  - PEM blocks: `-----BEGIN PRIVATE KEY-----`
  - Token prefixes: `sk-`, `ghp_`, `xoxb-`, `gsk_`, `AIza...`, `pplx-`
  - Telegram bot tokens: `\d{6,}:[A-Za-z0-9_-]{20,}`
- Config snapshot redaction (`src/config/redact-snapshot.ts`) with round-trip protection
- Gap: token refresh errors may include full tokens in error messages (H4)
- Gap: redacted sentinel string could collide with user data (M8)

**Transport:**

- TLS 1.3 minimum enforced at `src/infra/tls/gateway.ts:133-138`
- Auto-generated self-signed certs with 0o600 key permissions
- Gap: no SAN in auto-generated certs (M3)
- Gap: no cert rotation mechanism (H8)

**`.gitignore`:**

- `.env`, `memory/`, `.agent/*.json`, `local/`, `.local/` excluded
- iOS/Android build secrets excluded
- Recommendation: add `openclaw.json`, `auth.json`, `auth-profiles.json`, `device-auth.json` explicitly

### 4.4 Channel Security

**Discord** (`src/discord/`):

- Uses `@buape/carbon` library with Gateway WebSocket authentication
- No webhook endpoint (Gateway-only) — secure by design

**Slack** (`src/slack/`):

- Uses `@slack/bolt` HTTPReceiver for signature verification
- Socket Mode alternative with app token authentication
- Gap: signing secret defaults to empty string if undefined (H2)

**Telegram** (`src/telegram/`):

- grammY's `webhookCallback` with secret token
- Rate limiting via `@grammyjs/transformer-throttler`
- Update deduplication with ID tracking
- Gap: webhook secret token is optional (H1)

**LINE** (`src/line/`):

- HMAC-SHA256 signature verification with timing-safe comparison
- Best implementation across all channels — use as reference

**WhatsApp** (`src/web/`):

- Web client connection, no webhook endpoint
- Session-based authentication

**Signal** (`src/signal/`):

- signal-cli daemon with Unix socket — authentication delegated

**iMessage** (`src/imessage/`):

- BlueBubbles bridge — authentication delegated

### 4.5 Plugin Security

**Current State — Mitigated (first-step restrictions applied):**

- Plugins loaded via `jiti` in same process (`src/plugins/loader.ts`)
- Non-bundled plugins now receive:
  - Prominent security warning logged at load time
  - Redacted config (no `auth`, `env.vars`, `hooks.token`, `gateway.token`)
  - Restricted runtime (`runCommandWithTimeout` and `writeConfigFile` throw errors)
  - `sandboxed: true` flag set on tool context
- Bundled plugins retain full access (trusted)
- Plugins can still register hooks, tools, HTTP handlers, and gateway methods

**Remaining recommendations for full plugin sandboxing:**

1. Implement VM-based sandboxing (e.g., `isolated-vm`, Worker threads)
2. Add capability-based permissions (specific API access only)
3. Separate plugin processes with IPC
4. Plugin code signing and trust model
5. Resource limits (CPU, memory, network)

### 4.6 WebSocket Security

**Authentication — Excellent:**

- Token-based with timing-safe comparison (`src/gateway/auth.ts:40-44`)
- Password-based with timing-safe comparison
- Tailscale identity verification via whois
- Device auth with Ed25519 signature verification and nonce (v2)
- 10-minute clock skew tolerance for device signatures

**Message Limits:**

- Incoming: 512 KB (`MAX_PAYLOAD_BYTES`)
- Send buffer: 1.5 MB (`MAX_BUFFERED_BYTES`)
- Client receive: 25 MB (intentional asymmetry for screen snapshots)
- Slow clients dropped when buffer exceeds limit

**Origin Checking:**

- Validates Origin header against allowlist
- Allows same-host requests
- Allows localhost-to-localhost (gap: any port accepted — M2)

**Timeouts:**

- 10-second handshake timeout
- 30-second heartbeat interval

**Gaps:**

- No per-IP connection limits (H3)
- No message rate limiting (H3)
- Tailscale whois not cached — slow auth under load (H5 related)

---

## 5. Design Decisions Not to Change

These items were reviewed and determined to be acceptable:

| Item                            | Rationale                                                    |
| ------------------------------- | ------------------------------------------------------------ |
| Loopback-only default bind      | Secure default; exposing requires explicit config + auth     |
| Self-signed TLS certs           | Appropriate for local/Tailscale use; not for public internet |
| `ExecSecurity.full` mode exists | Needed for power users; requires explicit opt-in             |
| Wildcard allowlists             | Needed for group chats and broadcast channels                |
| 10-min device signature skew    | Accommodates mobile clock drift                              |
| 512 KB incoming payload limit   | Sufficient for all message types; prevents abuse             |

---

## 6. Recommended Priority Actions

### Immediate (Critical fixes)

- [x] **C2** — Re-validate SSRF policy on each redirect hop in `src/infra/net/fetch-guard.ts`
- [ ] **H1** — Make Telegram webhook secret mandatory (reject startup if not set in webhook mode)
- [ ] **H2** — Fix Slack signing secret to reject empty string with clear error message
- [x] **C4** — Add `blockOnSuspicious` config option to reject high-confidence prompt injection

### Short-term (High priority)

- [ ] **H3** — Add per-IP WebSocket connection limits and message rate limiting to gateway
- [ ] **H6** — Expand SSRF hostname blocklist: `169.254.169.254` (AWS), `metadata.azure.com`, `100.100.100.200` (Alibaba)
- [ ] **P1** — Add TTL-based cleanup to `agent-events.ts` registries (1-hour TTL, 5-min sweep)
- [ ] **P2** — Implement LRU eviction for memory index cache with proper `close()` on eviction
- [ ] **P3** — Add size limits to chat run registries with oldest-entry eviction
- [ ] **H5** — Deprecate device auth v1, require v2 with nonce for all new device auth flows
- [ ] **H4** — Redact tokens in OAuth error messages (show only last 4 chars)
- [ ] **H7** — Expand skill scanner rules: `rm -rf`, private IP network, dynamic imports, `vm`/`cluster` modules

### Medium-term

- [x] **C1** — Investigate plugin sandboxing (Worker threads with `isolated-vm`, capability-based permissions) — _first-step mitigation applied: security warnings, config redaction, restricted runtime, sandboxed flag_
- [x] **C3** — Add optional config encryption at rest (keychain-stored master key, `encrypted:...` sections) — _implemented: AES-256-GCM with macOS Keychain / file-based key_
- [ ] **H8** — Add TLS cert expiry check in audit, warn at 30 days remaining, consider auto-renewal
- [ ] **H10** — Add `openclaw auth revoke --profile=<id>` command for compromised tokens
- [ ] **M5** — Add file locking to device auth store using `proper-lockfile`
- [ ] **M3** — Add SAN to auto-generated TLS certs (`-addext "subjectAltName=DNS:localhost,DNS:*.ts.net"`)
- [ ] **P6** — Add stuck-process detection (4-hour timeout, SIGKILL, log warning)
- [ ] **P7** — Add size limit and global timeout to node registry pending invokes
- [ ] **P10** — Lazy-load heavy modules in `server.impl.ts` (browser, canvas, channel plugins)

### Low priority / nice-to-have

- [ ] **M1** — Use full Unicode confusables database for marker sanitization
- [ ] **M2** — Add port matching for loopback origin checks
- [ ] **M7** — Add `strictEnvSubstitution` config option to error on missing env vars
- [ ] **M8** — Use per-operation random UUID for redaction sentinels
- [ ] **M10** — Add config option for custom trusted/world Windows ACL principals
- [ ] **M11** — Default channel access policy to `allowlist` instead of allowing `open`
- [ ] **P5** — Clear debounce timer before closing config watcher
- [ ] **P8** — Fix cron job timeout cleanup with try-finally
- [ ] **P9** — Track consecutive health refresh failures, alert at threshold
- [ ] **P11** — Stringify broadcast frames once, send same buffer to all clients
- [ ] **P12** — Maintain filtered client sets by event scope for O(1) broadcast lookup
- [ ] **P13** — Merge config loading into single pass with migration
- [ ] Add `.gitignore` entries: `openclaw.json`, `auth.json`, `auth-profiles.json`, `device-auth.json`
- [ ] Add pre-commit hook to run `detect-secrets scan`

---

## 7. Essential Files for Security Review

### Authentication & Authorization

| File                                 | Purpose                                            |
| ------------------------------------ | -------------------------------------------------- |
| `src/gateway/auth.ts`                | Gateway authentication (timing-safe, multi-method) |
| `src/gateway/device-auth.ts`         | Device signature verification (Ed25519)            |
| `src/gateway/origin-check.ts`        | Origin header validation                           |
| `src/gateway/server-constants.ts`    | Payload/buffer size limits, timeouts               |
| `src/agents/auth-profiles/store.ts`  | OAuth token storage (encrypted at rest)            |
| `src/agents/auth-profiles/crypto.ts` | AES-256-GCM encryption for auth store              |
| `src/agents/auth-profiles/oauth.ts`  | Token refresh logic                                |
| `src/agents/cli-credentials.ts`      | External CLI credential integration                |
| `src/infra/device-auth-store.ts`     | Device auth token persistence                      |

### Network Security

| File                           | Purpose                                            |
| ------------------------------ | -------------------------------------------------- |
| `src/infra/net/ssrf.ts`        | SSRF protection, private IP detection, DNS pinning |
| `src/infra/net/fetch-guard.ts` | Guarded fetch with redirect handling               |
| `src/infra/tls/gateway.ts`     | TLS configuration, cert generation                 |

### Audit & Scanning

| File                               | Purpose                          |
| ---------------------------------- | -------------------------------- |
| `src/security/audit.ts`            | Main security audit orchestrator |
| `src/security/audit-fs.ts`         | Filesystem permission checks     |
| `src/security/audit-extra.sync.ts` | Config secrets detection         |
| `src/security/external-content.ts` | Prompt injection detection       |
| `src/security/skill-scanner.ts`    | Skill code safety scanning       |

### Credential & Secret Management

| File                            | Purpose                              |
| ------------------------------- | ------------------------------------ |
| `src/logging/redact.ts`         | Log redaction engine                 |
| `src/config/redact-snapshot.ts` | Config snapshot redaction            |
| `src/infra/json-file.ts`        | File I/O with permission enforcement |
| `src/agents/model-auth.ts`      | Provider API key resolution          |

### Command Execution

| File                              | Purpose                         |
| --------------------------------- | ------------------------------- |
| `src/agents/bash-tools.exec.ts`   | Command execution with approval |
| `src/agents/bash-tools.shared.ts` | Shared bash utilities           |
| `src/agents/sandbox-paths.ts`     | Path traversal prevention       |
| `src/infra/exec-approvals.ts`     | Approval socket and UI          |
| `src/infra/exec-safety.ts`        | Executable safety checks        |

### Channel Security

| File                              | Purpose                            |
| --------------------------------- | ---------------------------------- |
| `src/line/signature.ts`           | LINE HMAC verification (exemplary) |
| `src/slack/monitor/provider.ts`   | Slack signing secret handling      |
| `src/telegram/webhook.ts`         | Telegram webhook secret            |
| `src/channels/allowlist-match.ts` | Allowlist core logic               |
| `src/channels/command-gating.ts`  | Command authorization              |

### Plugin System

| File                           | Purpose                     |
| ------------------------------ | --------------------------- |
| `src/plugins/loader.ts`        | Plugin loading (no sandbox) |
| `src/plugins/runtime/index.ts` | Plugin API surface          |
| `src/plugins/types.ts`         | Plugin type definitions     |

### Performance-Critical

| File                                  | Purpose                        |
| ------------------------------------- | ------------------------------ |
| `src/gateway/server-chat.ts`          | Message handling hot path      |
| `src/gateway/server-broadcast.ts`     | WebSocket broadcast            |
| `src/gateway/server.impl.ts`          | Gateway orchestration, imports |
| `src/infra/agent-events.ts`           | Event tracking registry        |
| `src/memory/manager.ts`               | Memory index cache             |
| `src/agents/bash-process-registry.ts` | Process lifecycle              |
| `src/gateway/node-registry.ts`        | Node connection management     |
