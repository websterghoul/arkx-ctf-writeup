# LinkedIn post — ARKX AI Agent & MCP Security CTF

## Main post (copy from here)

Six AI agent CTF levels. Six accepted flags. One recurring mistake:

**The guardrail was in the conversation — while the capability stayed switched on.**

Over three sessions against the live *ARKX — AI Agent Security* CTF platform (`ctf.arkx.ninja`, attributed to CyberArk Labs), I exploited and documented six agentic/MCP vulnerability classes:

🔴 **Bad Robot** — `eval()` in a tool (CWE-95). The flag came out of an interpreter *error message*, because the author's blocklist died to a string concatenation.
🟠 **Master of Resources** — MCP resource over-exposure (CWE-284). `resources/list` advertised the secret; `unlock_flag` was callable by the same client that wanted to read it. Four JSON-RPC requests, no exploit code.
🔴 **Blind Network Ninja** — blind OS command injection (CWE-78). Output was suppressed, so I exfiltrated out-of-band through the level's own log viewer.
🔴 **The Shape Shifter** — insecure YAML deserialization (CWE-502). One `!!python/object/apply` tag = code execution.
🟠 **The Octopus** — credential leak in a refusal message + a writable authorization cache (CWE-209 + CWE-290).
🟠 **The Heist** — TOCTOU race (CWE-367). The "check" wasn't in the backend at all — it was the model's own prudence, which is steerable by anyone who can write text into the context.

What ties them together is boring and important: untrusted input treated as code, authorization delegated to a layer that can't enforce it, tools scoped far wider than their purpose, and safety checks left *advisory* instead of *atomic*.

If your product ships an agent with tools, read your tool scopes and your error messages today. Especially the error messages.

Full write-up with the exact prompts, payloads, raw MCP session transcripts, screenshots of every accepted flag, and remediation for each class is on Medium 👇 (link in first comment)

#AISecurity #AppSec #PenetrationTesting #LLM #MCP #CyberSecurity #RedTeam

## First comment (post this immediately after, it keeps the main post's reach intact)

Full write-up here: **[PASTE MEDIUM LINK]** — six chapters, 24 screenshots, every payload and the platform's verbatim replies. Happy to walk anyone through any of the six; DMs open.

---

## How to share the Medium article to LinkedIn

**Option A — native share link (fastest, cleanest preview).** Publish the Medium story first, then open:

`https://www.linkedin.com/sharing/share-offsite/?url=<URL-ENCODED-MEDIUM-URL>`

LinkedIn will render the article's title, subtitle and cover image as a card. Add your intro text above the card, then post.

**Option B — from Medium itself.** On your published story page, click the share icon → **LinkedIn**. This posts the same card but you get no control over the accompanying text, so you'd then edit the post to add the hook above.

**Option C — LinkedIn article / newsletter.** Paste the Medium piece into a LinkedIn article for readers who never leave the platform. Costs you a duplicate and no longer points at Medium, so only do it if you'd rather grow on LinkedIn than on Medium.

**Option D — the API, from this repo.** [publish_linkedin.js](publish_linkedin.js) posts the "Main post" section
above through LinkedIn's Posts API and then adds the "First comment" section on the new post, with the
Medium URL filled in. It needs an access token from a LinkedIn app with the **Share on LinkedIn** product
(`w_member_social`, plus `w_member_social_feed` for the comment). Put the token in `posts/.linkedin_token`
(already gitignored) or `LINKEDIN_ACCESS_TOKEN`, then:

```bash
node posts/publish_linkedin.js --whoami                                  # prints your urn:li:person:…
node posts/publish_linkedin.js --url https://medium.com/@you/story-slug    # dry run: shows both payloads
node posts/publish_linkedin.js --url https://medium.com/@you/story-slug --publish
```

Tokens last 60 days, and member posting is rate-limited per minute — the script retries a 429 twice
before giving up. It never prints the token.

### Publishing checklist

1. Publish on Medium **first** (a live URL is what makes the LinkedIn preview card work).
2. Set the Medium title and subtitle; upload a cover image (the MISSION ACCOMPLISHED screenshot from the report works well — redact the flag if you'd rather not publish one).
3. Add the tags listed at the bottom of the Medium draft.
4. Post the LinkedIn text above, then add the Medium link as the **first comment** — or do both in one step with Option D.
5. Pin that comment so it appears under the post.
6. Optionally reply to every comment for the first two hours — early engagement is what pushes the post beyond your immediate network.

### If you'd rather not publish the flags

The Medium article doesn't quote flag strings except where a payload shows one inside an error message or tool reply. To remove them, replace `flag-1a094e`, `flag-d39d05`, `flag-788808`, `flag-8b34bd`, `flag-ce352f` and `flag-14ab1b` with `<redacted>` — the exploit chains, the CWEs and every lesson still read perfectly.
