# ARKX CTF — AI Agent & MCP Security Writeup

A complete, evidence-backed writeup of the **ARKX "AI Agent Security" CTF** (`ctf.arkx.ninja`, attributed to CyberArk Labs): **27 of 27 levels solved** — 7/7 Beginner, 9/9 Advanced, 8/8 Expert, 3/3 DEFCON.

Every level below was solved against a live instance in October 2026, and each entry records the surface, the exact request that worked, and the design decision that made it possible. Flags are per-container: a fresh pod issues a new value, the technique does not change.

> **Authorisation.** This was the CTF's own platform, played with an account issued for the purpose. Nothing outside `ctf.arkx.ninja` was touched.

## The through-line

The levels are not really about jailbreaking a model. Across the set, the winning move was almost always an authorization decision that had been turned into *interpretation*:

- **The authorization decision is usually a value the caller supplies** — `scan_mode`, a passkey from a tool description, `Status: DECLASSIFIED`, `offset 1`, `SUPERVISOR-001`, `approved=true`, a badge JSON from a QR code, a support ticket, a nonce echo. In each case the guard asked the model to interpret the caller's string instead of looking up an immutable fact.
- **Secrets live where the model can be asked about them** — tool descriptions, debug logs, error messages, MCP resource catalogues. Anything the model can be asked about is public.
- **The check and the action disagree about the world** — a filter that runs before percent-decoding, a path check that inspects spelling instead of resolving, a balance read and debited in separate steps, a copy tool that was never scoped because only reads were.

## Contents

| Path | What it is |
| --- | --- |
| [`report/AI_Agent_MCP_Security_Verified_Vulnerability_Report.pdf`](report/AI_Agent_MCP_Security_Verified_Vulnerability_Report.pdf) | Consolidated vulnerability report — findings, severity, mappings (PDF) |
| [`report/AI_Agent_MCP_Security_Verified_Vulnerability_Report.docx`](report/AI_Agent_MCP_Security_Verified_Vulnerability_Report.docx) | Same report, editable |
| [`report/ARKX_AI_Agent_Security_CTF_Solution_Report.pdf`](report/ARKX_AI_Agent_Security_CTF_Solution_Report.pdf) | Level-by-level solution report |
| [`report/full_report.html`](report/full_report.html) | Long-form report with screenshots and payload tables |
| [`report/report.html`](report/report.html) | Single-file HTML report |
| [`report/payload_cookbook.md`](report/payload_cookbook.md) | Payloads that worked, per level, with the observed response |
| [`report/payloads_by_vulnerability.md`](report/payloads_by_vulnerability.md) | Same payloads indexed by vulnerability class |
| [`report/exploit_L7_master_of_resources.md`](report/exploit_L7_master_of_resources.md) | Deep dive: MCP server exposure (Level 7) |
| [`report/L7_rpc_table.md`](report/L7_rpc_table.md), [`report/L7_rpc_table_live.md`](report/L7_rpc_table_live.md) | MCP JSON-RPC request/response table, incl. a live capture |
| [`report/arkx-level-7-report.html`](report/arkx-level-7-report.html), `.pdf` | Standalone report for the MCP level |
| [`report/tools/`](report/tools/) | Scripts used to build the reports and reproduce individual steps |
| [`posts/medium_post.md`](posts/medium_post.md) | Long-form article version |
| [`posts/linkedin_post.md`](posts/linkedin_post.md) | Short social version |

## Track summaries

**Beginner (7/7)** — the secret is in the wrong place: tool descriptions, debug logs, path handling, a self-attested classification, a model-chosen parameter, and a shell string.

**Advanced (9/9)** — the authorization check is a judgement: environment disclosure, invented clearance, conversational verification, an oracle, an `eval()`, SSRF into an internal metadata service, an MCP catalogue, a response filter, and blind command injection exfiltrated through the platform's own log viewer.

**Expert (8/8)** — trust boundaries inside the tool chain: client-supplied approval flags, ownership re-assignment, post-check decoding, forged vision/QR data, RAG poisoning, unsafe YAML deserialization, a credential leaked in an error and written back into an authorization cache, and a TOCTOU double-spend.

**DEFCON (3/3)** — memory and crypto: an aarch64 stack overflow exploited with ret2stack shellcode (ASLR off, executable stack, unbounded `fread`), AES-ECB block splicing for role forgery, and an A2A endpoint whose nonce-response challenge proves only that the caller can read the previous message.

## Full writeup

The running writeup, with a Mechanism / Exploit / Root-cause breakdown for all 27 levels, lives in Notion:

**https://app.notion.com/p/AI-Agent-and-MCP-Security-Assessment-ARKX-CTF-Writeup-3faa6975670c807fb8ede0d7b7a7b03c**

## Not in this repository

The working directory used during the engagement (`.work/`) is deliberately excluded: it holds live session cookies (`idToken`, `accessToken`, `refreshToken`, `sessionId`) for the CTF account, plus transient transcripts and scratch scripts. The flags quoted throughout are the values their containers issued and are not reusable.
