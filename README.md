# ARKX CTF Writeup — AI Agent & MCP Security (27/27 levels solved)

Complete **ARKX CTF writeup** for the AI Agent Security challenge set at `ctf.arkx.ninja` (attributed to CyberArk Labs): **all 27 levels solved** — 7/7 Beginner, 9/9 Advanced, 8/8 Expert, 3/3 DEFCON. Every level covers the attack surface, the exact payload that worked, and the design flaw behind it, with AI agent security, LLM security and MCP (Model Context Protocol) security findings throughout.

Every level was solved against a live instance in October 2026; each entry records the surface, the exact request that worked, and the design decision that made it possible. Flags are per-container — a fresh pod issues a new value, the technique does not change.

> **Authorisation.** This was the CTF's own platform, played with an account issued for the purpose. Nothing outside `ctf.arkx.ninja` was touched.

## TL;DR for defenders

The set is not really about jailbreaking a model. The winning move was almost always an authorization decision that had been turned into *interpretation*:

- **The authorization decision is a value the caller supplies** — `scan_mode`, a passkey read out of a tool description, `Status: DECLASSIFIED`, `offset 1`, `SUPERVISOR-001`, `approved=true`, a badge JSON decoded from a QR code, a support ticket, a nonce echo. The guard asks the model to interpret the caller's string instead of looking up an immutable fact.
- **Secrets live where the model can be asked about them** — tool descriptions, debug logs, error messages, MCP resource catalogues. Anything the model can be asked about is public.
- **The check and the action disagree about the world** — a filter that runs before percent-decoding, a path check that inspects spelling instead of resolving, a balance read then debited in separate steps, a copy tool that was never scoped because only reads were.

## All 27 levels

| # | Challenge | What broke | Class |
| --- | --- | --- | --- |
| B1 | The Context Gateway | Debug log prints the `SCAN_MODE` that gates the hidden service | Info disclosure (CWE-200) |
| B2 | The Magic Door | Passkey written into the tool's own description | Secret in metadata (CWE-798) |
| B3 | The Lost Archives: Part 1 | Traversal + authorization delegated to the model | Path traversal (CWE-22 / CWE-863) |
| B4 | The File Manager | Flag sits inside the tool's working directory | Broken access control (CWE-284) |
| B5 | The Mailman | `Status: DECLASSIFIED` trusted from the conversation | Authz by assertion (CWE-863) |
| B6 | The Scheduler | Maintenance policy evaluated on a caller-chosen `offset` | Parameter tampering (CWE-863) |
| B7 | Network Ninja | `ping` built by string concatenation | OS command injection (CWE-78) |
| A1 | Context Gateway | Health check echoes its environment; `DBG-8821` unlocks discovery | Info disclosure (CWE-200) |
| A2 | Magic Door | Invented `SUPERVISOR-001` accepted — shape checked, not identity | Broken authentication (CWE-287) |
| A3 | Archivist | Declassification negotiated in conversation | Policy bypass (CWE-863) |
| A4 | Mastermind | 4-digit PIN, graded feedback, no lockout — 1606 | Brute force (CWE-307) |
| A5 | Bad Robot | `eval()` behind a keyword blocklist, errors echoed | Code injection (CWE-94) |
| A6 | Enemy Within | Fetch tool reaches loopback metadata, token then flag | SSRF (CWE-918) |
| A7 | Master of Resources | MCP `resources/list` exposes `resource://flag`; `unlock_flag` is self-service | MCP exposure (CWE-200 / CWE-306) |
| A8 | Silent Transmission | DLP filters the visible reply, not the channel | Exfiltration (CWE-201) |
| A9 | Blind Network Ninja | Blind injection; flag shipped out through `/level/9/logs` | Blind OS injection (CWE-78) |
| E1 | The Manager | Backup codes released to a well-framed "weekend batch" story | Broken authorization (CWE-863) |
| E2 | The Lost Archives: Part 2 | `copy_file` un-scoped — reads restricted, copies are not | Exfiltration (CWE-200) |
| E3 | The Lost Archives: Part 1 (Hard) | Filter checks literals, decode happens after — `%2e%2e%2f` | Traversal (CWE-22 / CWE-180) |
| E4 | The All Seeing Eye | QR badge JSON trusted as identity; `level: 99` from the caller | Forged identity (CWE-347) |
| E5 | The Trojan Horse | Authorization memo stored in the writable RAG corpus | RAG poisoning (OWASP LLM01) |
| E6 | The Shape Shifter | Full YAML loader resolves `!!python/...` object tags | Insecure deserialization (CWE-502) |
| E7 | The Octopus | Error leaks the admin key; cache that holds it is caller-writable | Secret leak (CWE-209 / CWE-639) |
| E8 | The Heist | Two `execute_order` calls in one turn, both see $1000 | TOCTOU (CWE-367) |
| D1 | The Smashed File Manager | Unbounded `fread` into 512 bytes, ASLR off, exec stack — ret2stack aarch64 shellcode | Stack overflow (CWE-121) |
| D2 | The Keymaker | `AES-128-ECB` token, block splicing for `role=admin` | Broken crypto (CWE-327) |
| D3 | The Diplomat | A2A nonce-response rejects nothing — echo the nonce back | Broken authentication (CWE-287) |

## Contents

| Path | What it is |
| --- | --- |
| [`report/AI_Agent_MCP_Security_Verified_Vulnerability_Report.pdf`](report/AI_Agent_MCP_Security_Verified_Vulnerability_Report.pdf) | Consolidated vulnerability report — findings, severity, mappings (PDF) |
| [`report/ARKX_AI_Agent_Security_CTF_Solution_Report.pdf`](report/ARKX_AI_Agent_Security_CTF_Solution_Report.pdf) | Level-by-level solution report |
| [`report/full_report.html`](report/full_report.html) | Long-form report with screenshots and payload tables |
| [`report/report.html`](report/report.html) | Single-file HTML report |
| [`report/payload_cookbook.md`](report/payload_cookbook.md) | Payloads that worked, per level, with the observed response |
| [`report/payloads_by_vulnerability.md`](report/payloads_by_vulnerability.md) | Same payloads indexed by vulnerability class |
| [`report/exploit_L7_master_of_resources.md`](report/exploit_L7_master_of_resources.md) | Deep dive: MCP server exposure (Level 7) |
| [`report/L7_rpc_table.md`](report/L7_rpc_table.md), [`report/L7_rpc_table_live.md`](report/L7_rpc_table_live.md) | MCP JSON-RPC request/response table, incl. a live capture |
| [`report/L7_live_session.txt`](report/L7_live_session.txt) | Raw terminal transcript behind the live capture (evidence) |
| [`report/arkx-level-7-report.html`](report/arkx-level-7-report.html), `.pdf` | Standalone report for the MCP level |
| [`report/img/`](report/img/) | Screenshots: solved screen, takeaways, agent interaction, flag accepted — per level |

![ARKX CTF level solved screen showing the flag accepted](report/img/04_flag_accepted.png)

## Track summaries

**Beginner (7/7)** — the secret is in the wrong place: tool descriptions, debug logs, path handling, a self-attested classification, a model-chosen parameter, and a shell string.

**Advanced (9/9)** — the authorization check is a judgement: environment disclosure, invented clearance, conversational verification, an oracle, an `eval()`, SSRF into an internal metadata service, an MCP catalogue, a response filter, and blind command injection exfiltrated through the platform's own log viewer.

**Expert (8/8)** — trust boundaries inside the tool chain: client-supplied approval flags, ownership re-assignment, post-check decoding, forged vision/QR data, RAG poisoning, unsafe YAML deserialization, a credential leaked in an error and written back into an authorization cache, and a TOCTOU double-spend.

**DEFCON (3/3)** — memory and crypto: an aarch64 stack overflow exploited with ret2stack shellcode (ASLR off, executable stack, unbounded `fread`), AES-ECB block splicing for role forgery, and an A2A endpoint whose nonce-response challenge proves only that the caller can read the previous message.

## Full writeup

The running writeup, with a Mechanism / Exploit / Root-cause breakdown for all 27 levels, lives in Notion:

**https://app.notion.com/p/AI-Agent-and-MCP-Security-Assessment-ARKX-CTF-Writeup-3faa6975670c807fb8ede0d7b7a7b03c**

## Topics covered

AI agent security · LLM security · Model Context Protocol (MCP) security · prompt injection (direct and indirect) · RAG poisoning · tool poisoning and tool-description secrets · excessive agency · broken authorization in agentic workflows · SSRF into cloud metadata · OS command injection (blind and reflected) · path traversal and filter/normalisation mismatches · insecure deserialization · sensitive data in error messages · TOCTOU and race conditions · memory corruption (aarch64 stack overflow, ret2stack) · weak cryptography (AES-ECB cut-and-paste) · Agent-to-Agent (A2A) protocol authentication · OWASP Top 10 for LLM Applications · CWE mapping · detection and remediation guidance.

## Not in this repository

Only the writeups are published here. Everything else was kept back deliberately:

- **Engagement working directory** (`.work/`) — live session cookies (`idToken`, `accessToken`, `refreshToken`, `sessionId`) for the CTF account, plus transient transcripts and scratch scripts.
- **Build tooling** — the Node/Playwright scripts that rendered the PDFs, drove the headless browser and proxied the level UI, and the exploit helper shell script. They embed environment-specific paths and are not needed to follow the writeup.
- **Article drafts** — the long-form and short social versions of this writeup.
- **Editable report source** — the `.docx` from which the vulnerability-report PDF was generated.

The flags quoted throughout are the values their containers issued and are not reusable.
