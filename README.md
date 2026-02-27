<h1 align="center">OmniStrike</h1>

<p align="center">
  <strong>One extension to replace them all.</strong><br>
  15 active scanners, 4 passive analyzers, SQL exploitation engine, AI-powered analysis — single JAR.
</p>

<p align="center">
  <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/badge/version-1.35-blue?style=flat-square" alt="Version"></a>
  <img src="https://img.shields.io/badge/Java-17+-orange?style=flat-square&logo=openjdk" alt="Java 17+">
  <img src="https://img.shields.io/badge/Burp_Suite-Montoya_API-E8350E?style=flat-square" alt="Montoya API">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=flat-square" alt="License"></a>
  <a href="https://github.com/worldtreeboy/OmniStrike/stargazers"><img src="https://img.shields.io/github/stars/worldtreeboy/OmniStrike?style=flat-square&color=yellow" alt="Stars"></a>
  <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/github/downloads/worldtreeboy/OmniStrike/total?style=flat-square&color=green" alt="Downloads"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#modules">Modules</a> &bull;
  <a href="#omnimap-exploiter">OmniMap</a> &bull;
  <a href="#websocket-scanner">WebSocket Scanner</a> &bull;
  <a href="#deserialization-payload-generator">Deser Generator</a> &bull;
  <a href="#ai-scanning">AI Scanning</a> &bull;
  <a href="#building-from-source">Build</a>
</p>

---

## Quick Start

```
1. Download omnistrike.jar from Releases
2. Burp Suite → Extensions → Add → Java → select omnistrike.jar
3. Set target scope, click Start — scan while you browse
4. Or right-click any request → Send to OmniStrike
```

---

## Modules

### Active Scanners (15)

| Module | What it does |
|---|---|
| **SQLi Detector** | Auth bypass, error-based, UNION, time-based blind (3-step verification), boolean-blind (2-round), 64 OOB payloads. ~375 payloads/param across 10 database engines. |
| **OmniMap Exploiter** | Post-detection SQL injection exploitation engine — sqlmap-equivalent payloads. 4 techniques: UNION, Error-based, Boolean blind, Time-based blind. 5 DBMS dialects (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), DBMS-agnostic detection, auto boundary/DBMS detection, NEGATIVE WHERE mode, parallel character extraction, adaptive bisection, predictive optimization, WAF bypass tamper engine. [Details below](#omnimap-exploiter). |
| **XSS Scanner** | 6 reflection contexts, smart filter probing (only sends viable payloads), adaptive evasion generation, DOM XSS flow analysis, CSTI, framework-specific payloads (AngularJS/Angular/Vue/React/jQuery), blind XSS via Collaborator. |
| **SSRF Scanner** | Collaborator OOB, cloud metadata with multi-marker validation (AWS/Azure/GCP/Oracle), DNS rebinding, 49 localhost bypasses, 31 protocol smuggling payloads (gopher, LDAP, etc). |
| **SSTI Scanner** | 20 template engines, large-number canaries (131803 not 49), template syntax consumption verification, 32 OOB payloads. |
| **Command Injection** | 3-step time-based, structural regex output matching, 140 payloads/param (Unix + Windows), `$IFS`/`%0a`/backtick/double-encoding bypasses. |
| **XXE Scanner** | 4-phase: XML body, XInclude, JSON→XML, Content-Type forcing. UTF-16 bypass, SAML detection, 14 OOB payloads. |
| **Deserialization** | 6 languages, 137+ gadget chains, passive fingerprinting, OOB-first Collaborator detection, blind spray mode. [Details below](#deserialization-scanner). |
| **WebSocket Scanner** | Passive frame analysis + OOB-first active fuzzing across 8 injection categories (CSWSH, SQLi, CmdI, SSRF, SSTI, XSS, IDOR, AuthZ bypass). [Details below](#websocket-scanner). |
| **GraphQL** | 7-phase: introspection (4 bypasses), schema analysis, injection (SQLi/NoSQLi/CMDi/SSTI/traversal), IDOR, DoS config, HTTP-level, error disclosure. Auto-generates queries from schema. |
| **CORS** | Reflected origin, null trust, subdomain trust, scheme downgrade, wildcard+credentials, preflight bypass. |
| **Cache Poisoning** | 30 unkeyed header vectors, 29 unkeyed query params, cacheability analysis, poison confirmation. |
| **Host Header Injection** | Password reset poisoning via Collaborator, routing SSRF, duplicate Host, override headers. |
| **HTTP Parameter Pollution** | Duplicate param precedence, privilege escalation patterns, WAF bypass via splitting. |
| **Prototype Pollution** | Server-side `__proto__`/`constructor.prototype` with canary persistence verification, behavioral gadgets. |
| **Path Traversal / LFI** | Absolute path + traversal, 24 Unix / 9 Windows targets with structural content validation, 26 encoding bypasses, PHP wrappers (filter/data/iconv). |

### Passive Analyzers (4)

| Module | What it does |
|---|---|
| **Client-Side Analyzer** | DOM XSS source-to-sink, prototype pollution, hardcoded secrets with entropy validation, postMessage, open redirects, endpoint extraction. Auto-skips minified libraries. |
| **Hidden Endpoint Finder** | Extracts API endpoints and paths from JS/HTML/JSON via 13+ regex patterns. |
| **Subdomain Collector** | Discovers subdomains from CSP, CORS, redirects, and response bodies. |
| **Security Header Analyzer** | HSTS, CSP, CORS, cookie flags, X-Frame-Options, Referrer-Policy, server version disclosure. |

---

## Deserialization Scanner

**6-language coverage** with passive fingerprinting, active injection, and OOB-first Collaborator detection:

| Language | Chains | Highlights |
|---|---|---|
| **Java** | 34 | Full ysoserial coverage (CommonsCollections 1-7, Spring, Hibernate, Groovy, C3P0, ROME, etc), 19 OOB payloads |
| **.NET** | 32 gadgets × 9 formatters | ysoserial.net-style Gadget + Formatter dropdowns, 9 OOB payloads |
| **PHP** | 47 | phpggc port — Laravel, Symfony, Monolog, Guzzle, WordPress, Doctrine, CodeIgniter4, ThinkPHP + 8 more frameworks. Configurable function dropdown (system/exec/passthru/etc). 3 OOB payloads |
| **Python** | 26 | Pickle protocol 0/2/4, PyYAML, jsonpickle, reverse shell. 12 OOB payloads |
| **Ruby** | 13 | Gem gadgets, Rails ActiveSupport, YAML/Psych, Oj library. Proper Marshal binary encoding. 5 OOB payloads |
| **Node.js** | 17 | node-serialize, serialize-javascript, js-yaml, cryo, funcster, prototype pollution. 12 OOB payloads |

38 suspect cookie patterns. Blind spray mode when no serialized data detected. OOB-first: if Collaborator confirms, remaining phases skipped.

---

## Deserialization Payload Generator

Standalone tool for generating deserialization payloads — no external tools needed (replaces ysoserial, ysoserial.net, phpggc).

- **137+ chains** across Java, .NET, PHP, Python, Ruby, Node.js
- **.NET**: Gadget + Formatter two-dropdown UX (32 gadgets × 9 formatters)
- **PHP**: Function dropdown (system, exec, passthru, shell_exec, popen, etc) — phpggc-style
- **Encodings**: Raw, Base64, URL-encoded, Base64+URL-encoded
- **Preview**: Terminal-style dark preview with selectable text color
- **Copy**: One-click Base64 or raw clipboard copy
- **Context menu**: Right-click in Proxy/Repeater to open directly

---

## WebSocket Scanner

Intercepts WebSocket frames via Burp's proxy and provides both passive analysis and on-demand active fuzzing.

**Passive Analysis** (runs automatically on every intercepted frame):
- Sensitive data: credit cards (Luhn-validated), SSNs, API keys, passwords, JWTs
- PII: email addresses, phone numbers
- Connection issues: unencrypted `ws://`, missing Origin header, session-less connections, auth tokens in URL
- Error leakage: SQL error strings, stack traces in server responses

**Active Fuzzing** (click "Scan" on a connection — OOB-first strategy):

| Category | OOB Phase | In-Band Fallback | Confidence |
|---|---|---|---|
| CSWSH | N/A (binary accept/reject) | Origin validation test | CERTAIN |
| SQL Injection | xp_dirtree, extractvalue, COPY | Error-based (SQL error string match) | CERTAIN / FIRM |
| Command Injection | nslookup, curl, ping | Time-based (3x statistical, >=4s delta) | CERTAIN / FIRM |
| SSRF | Collaborator URLs in URL params | None (blind SSRF) | CERTAIN |
| SSTI | Multi-engine nslookup | Math eval ({{7*7}}→49) | CERTAIN / FIRM |
| XSS | img onerror fetch | Canary reflection detection | CERTAIN / FIRM |
| IDOR | N/A | ID substitution + response diff | TENTATIVE |
| AuthZ Bypass | N/A | Auth vs unauth response comparison | FIRM |

---

## OmniMap Exploiter

Post-detection SQL injection exploitation engine — extracts databases, tables, columns, and data from confirmed injection points. All payloads sourced directly from sqlmap.

**4 Extraction Techniques** (tested in order: Error > Boolean > Time > UNION; extraction preference: UNION > Error > Boolean > Time):

| Technique | Speed | How it works |
|---|---|---|
| **UNION** | Fastest | Full row per request via `UNION ALL SELECT`. NEGATIVE WHERE mode (replaces original value with `-1` so only UNION data appears). DBMS-aware hex markers (`0x` for MySQL, `CHR()` for others). |
| **Error-based** | Fast | Leaks data inside DBMS error messages. MySQL: EXTRACTVALUE, UPDATEXML, FLOOR, GTID_SUBSET, BIGINT, EXP, JSON_KEYS. PostgreSQL: CAST. MSSQL: IN/CONVERT/CONCAT. Oracle: XMLType (with REPLACE escapes for space/$/@/#), UTL_INADDR, CTXSYS, DBMS_UTILITY. Inference fallback when errors are suppressed. |
| **Boolean blind** | Medium | Bisection via true/false page comparison. Parallel multi-threaded character extraction. RLIKE vector support for MySQL. Adaptive tiers (a-z > 0-9 > full ASCII). |
| **Time-based blind** | Slowest | DBMS-agnostic detection — tries ALL 5 DBMS sleep functions regardless of detected DBMS. MySQL: SLEEP, IF, RLIKE, ELT, MAKE_SET, BENCHMARK. PostgreSQL: PG_SLEEP, GENERATE_SERIES. MSSQL: WAITFOR DELAY, sysusers heavy query. Oracle: DBMS_PIPE, DBMS_LOCK, ALL_USERS heavy query. SQLite: RANDOMBLOB. Zero-sleep validation + consistency checks. |

**How it works**:
1. Right-click any request → **Send to OmniMap Exploiter**
2. Select the injectable parameter, DBMS (or auto-detect), techniques, and what to extract
3. Click **Exploit** — OmniMap auto-detects the injection boundary, fingerprints the DBMS, and extracts data

**Capabilities**:
- **5 DBMS dialects**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite — each with correct syntax for string functions, pagination, schema queries
- **Auto boundary detection**: Tests prefix/suffix combinations (single quote, double quote, parentheses, comments) like sqlmap
- **3-strategy DBMS fingerprinting**: Error-based (error message patterns) > Boolean (DB-specific functions: CONNECTION_ID, PG_BACKEND_PID, @@SPID, BITAND, SQLITE_VERSION) > Time-based (successful sleep payload identifies DBMS)
- **DBMS re-detection**: If time-based detection identifies a different DBMS than error/boolean detection, the dialect is automatically updated for extraction
- **Parallel character extraction**: Multi-threaded bisection for boolean/error-inference modes
- **Adaptive bisection**: Tests common ranges first (a-z > 0-9 > full ASCII), saving ~30% requests
- **Predictive optimization**: Tests common table/column names before falling back to bisection
- **Level/Risk system**: Level 1-5 controls boundary complexity and payload count. Risk 1-3 controls payload intrusiveness (Risk 3 enables OR-based payloads)
- **WAF bypass**: 9 tamper transforms (space2comment, randomCase, charencode, etc.)
- **Full UI**: Config dialog with technique selection, database tree view, data table with CSV export, live request log

---

## AI Scanning

Right-click any request to trigger AI analysis. Never auto-fires — zero wasted tokens.

**Capabilities**: Smart fuzzing, WAF fingerprinting + bypass, adaptive multi-round scanning (up to 5 rounds with full response feedback), cross-file batch analysis, payload learning from confirmed findings, Collaborator data exfiltration, fuzz history (remembers every payload per URL/param/vuln type), multi-step exploitation of confirmed vulns.

**Providers**:

| Provider | Models |
|---|---|
| Anthropic (Claude) | claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5-20251001 |
| OpenAI | gpt-5.2, gpt-4o, o3-mini |
| Google Gemini | gemini-3.1-pro, gemini-3-flash-preview, gemini-2.5-flash |

Also supports CLI tools: Claude Code, Gemini CLI, Codex CLI, OpenCode CLI.

> API keys stored in memory only — never persisted to disk.

---

## Usage

**Scope-based (hands-free)**: Set target scope → toggle modules → click Start → browse normally. All in-scope traffic scanned automatically.

**Right-click**: Right-click any request → Send to OmniStrike (All Modules), or pick a specific module. Per-parameter targeting available via Scan Parameter submenu.

**Time-based testing**: Disabled by default (slow, heavy traffic). Enable via checkbox in UI.

**Session keep-alive**: Right-click login request → Set as Session Login Request. Extension replays it periodically to keep cookies fresh.

---

## Detection Philosophy

- **Zero false positives**: Every finding requires structural proof — not just response differences
- **OOB-first**: Collaborator payloads fire before time-based/error-based; if OOB confirms, remaining phases skipped
- **Smart filter probing**: Probes which characters survive filtering, then sends only viable payloads
- **3-step timing**: Baseline → true delay → false must NOT delay
- **Deduplication**: Cross-module, normalized URL dedup
- **Request/response highlighting**: All 20 modules annotate findings with byte-range markers in Burp Dashboard

---

## Building from Source

```bash
git clone https://github.com/worldtreeboy/OmniStrike.git
cd OmniStrike
./gradlew shadowJar
# Output: build/libs/omnistrike.jar
```

Requires JDK 17+. Dependencies: montoya-api 2026.2, gson 2.11.0.

---

## Contributing

1. Fork and create a feature branch
2. `./gradlew shadowJar` must compile cleanly
3. Test against [DVWA](https://github.com/digininja/DVWA), [Juice Shop](https://github.com/juice-shop/juice-shop), or [PortSwigger Academy](https://portswigger.net/web-security)
4. Open a PR

[GitHub Issues](https://github.com/worldtreeboy/OmniStrike/issues) for bugs and feature requests.

---

## Changelog

### v1.35 (2026-02-28)
- **OmniMap: 4 techniques** — UNION, Error-based, Boolean blind, Time-based blind (was boolean-only)
- **UNION extraction**: ORDER BY column count detection, hex marker display column detection, NEGATIVE WHERE mode (sqlmap's WHERE.NEGATIVE), DBMS-aware marker encoding (CHR()/CHAR() for non-MySQL)
- **Error-based extraction**: All sqlmap error functions per DBMS with level gating, Oracle XMLType REPLACE() escapes for space/$/@/#, inference fallback mode (CASE WHEN + error trigger as boolean oracle)
- **Time-based detection**: DBMS-agnostic — tries ALL 5 DBMS sleep functions when DBMS is unknown, zero-sleep validation, consistency checks, RLIKE/ELT/MAKE_SET/DBMS_LOCK/BENCHMARK/heavy query payloads
- **DBMS re-detection**: Time-based payload success auto-updates dialect when it identifies a different DBMS than initial detection
- **Boolean blind**: RLIKE extraction vector support, matched detection label dispatch
- **PayloadInjector**: New `injectReplace` mode for UNION NEGATIVE WHERE

### v1.34 (2026-02-27)
- **OmniMap Exploiter**: SQL injection exploitation engine — boolean blind extraction via content-based conditional responses
- 5 DBMS dialects (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), auto boundary/DBMS detection, parallel multi-threaded character extraction, adaptive bisection, predictive optimization, WAF bypass tamper engine, full config dialog + results UI

### v1.33 (2026-02-27)
- **WebSocket Scanner**: New module — passive frame analysis (sensitive data, auth issues, error leakage) + OOB-first active fuzzing across 8 injection categories (CSWSH, SQLi, CmdI, SSRF, SSTI, XSS, IDOR, AuthZ bypass)
- **Custom WS UI panel**: Live connection dropdown, real-time message table with direction/search filters, scan controls, per-connection findings view

### v1.30 (2026-02-27)
- **Deserialization payload expansion**: 137+ chains (47 PHP from phpggc, 26 Python with Pickle v0/v2/v4, 17 Node.js, 13 Ruby)
- **PHP Function dropdown**: configurable callable (system/exec/passthru/etc)
- **Encoding-aware preview**: Base64 section only shows for RAW encoding

---

## Security Notice

OmniStrike is for **authorized penetration testing** and **security research** only. Use exclusively against systems you have written permission to test.
