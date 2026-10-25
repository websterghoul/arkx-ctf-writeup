#!/usr/bin/env node
/**
 * Publish posts/linkedin_post.md to LinkedIn with the REST Posts API.
 *
 * Reads the draft's two sections ("## Main post" and "## First comment"), converts them to
 * LinkedIn commentary text, and can create the post and then attach the first comment —
 * which is what the draft's publishing checklist asks for.
 *
 * Nothing is sent unless you pass --publish. The default is a dry run that prints exactly
 * what would be sent and how long it is.
 *
 * Credentials
 *   Token      LINKEDIN_ACCESS_TOKEN, or the file posts/.linkedin_token (gitignored).
 *              Needs a token from an app with the "Share on LinkedIn" product
 *              (w_member_social) — and w_member_social_feed for the comment call.
 *   Author     LINKEDIN_AUTHOR_URN (urn:li:person:XXXX), or LINKEDIN_MEMBER_ID, or
 *              discover it with --whoami (uses the token's /v2/userinfo `sub`).
 *
 * Usage
 *   node posts/publish_linkedin.js --whoami
 *   node posts/publish_linkedin.js                                  # dry run, both payloads
 *   node posts/publish_linkedin.js --url https://medium.com/...      # dry run with the link filled in
 *   node posts/publish_linkedin.js --url https://medium.com/... --publish
 *   node posts/publish_linkedin.js --comment-only --post-urn urn:li:share:123 --url https://medium.com/... --publish
 *
 * Env overrides: LINKEDIN_VERSION (default 202609), LINKEDIN_DRY_RUN=1 forces a dry run.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DRAFT = path.join(__dirname, 'linkedin_post.md');
const TOKEN_FILE = path.join(__dirname, '.linkedin_token');
const API = 'https://api.linkedin.com';
const VERSION = process.env.LINKEDIN_VERSION || '202609';
const POST_LIMIT = 3000; // LinkedIn commentary limit
const COMMENT_LIMIT = 1250; // LinkedIn comment limit
const PLACEHOLDER = '**[PASTE MEDIUM LINK]**';

// ---------------------------------------------------------------- arguments

function parseArgs(argv) {
  const opts = { publish: false, whoami: false, commentOnly: false, url: null, postUrn: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const [key, inline] = a.includes('=') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a, null];
    const take = () => (inline !== null ? inline : argv[++i]);
    switch (key) {
      case '--publish': opts.publish = true; break;
      case '--whoami': opts.whoami = true; break;
      case '--comment-only': opts.commentOnly = true; break;
      case '--url': opts.url = take(); break;
      case '--post-urn': opts.postUrn = take(); break;
      case '-h': case '--help': opts.help = true; break;
      default: throw new Error(`unknown option: ${a}`);
    }
  }
  if (process.env.LINKEDIN_DRY_RUN === '1') opts.publish = false;
  return opts;
}

function usage() {
  console.log(fs.readFileSync(__filename, 'utf8').split('*/')[0].split('/**')[1].replace(/^ \* ?/gm, '').trim());
}

// ---------------------------------------------------------------- credentials

function readToken() {
  if (process.env.LINKEDIN_ACCESS_TOKEN) return { token: process.env.LINKEDIN_ACCESS_TOKEN.trim(), from: 'LINKEDIN_ACCESS_TOKEN' };
  try {
    const token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
    if (token) return { token, from: path.relative(ROOT, TOKEN_FILE) };
  } catch { /* no file */ }
  return { token: null, from: null };
}

function resolveAuthor() {
  if (process.env.LINKEDIN_AUTHOR_URN) return process.env.LINKEDIN_AUTHOR_URN.trim();
  if (process.env.LINKEDIN_MEMBER_ID) return `urn:li:person:${process.env.LINKEDIN_MEMBER_ID.trim()}`;
  return null;
}

function headers(token) {
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    'X-Restli-Protocol-Version': '2.0.0',
    'Linkedin-Version': VERSION,
  };
}

// LinkedIn throttles member creation per minute (HTTP 429); retry a couple of times.
async function call(method, url, token, body, attempt = 1) {
  const res = await fetch(url, { method, headers: headers(token), body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  if (res.status === 429 && attempt < 3) {
    const wait = 20 * attempt;
    console.log(`  throttled (429), waiting ${wait}s before retry ${attempt + 1}/3…`);
    await new Promise((r) => setTimeout(r, wait * 1000));
    return call(method, url, token, body, attempt + 1);
  }
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON body */ }
  return { status: res.status, ok: res.ok, id: res.headers.get('x-restli-id'), json, text };
}

function explainFailure(what, res) {
  process.exitCode = 1; // a failed call must not look like a successful run to a script or CI
  console.error(`\n✗ ${what} failed — HTTP ${res.status}`);
  if (res.text) console.error(`  body: ${res.text.slice(0, 600)}`);
  if (res.status === 401) console.error('  → token missing, expired (60-day life) or malformed.');
  if (res.status === 403) console.error('  → token lacks the scope for this call. Posting needs w_member_social; commenting needs w_member_social_feed. Check the products on your LinkedIn app.');
  if (res.status === 404) console.error('  → wrong URN, or the post is not visible to this member.');
  if (res.status === 400) console.error('  → check the payload against the Posts/Comments API schema.');
}

// ---------------------------------------------------------------- draft parsing

function section(lines, startMatch, stopMatches) {
  const start = lines.findIndex((l) => startMatch.test(l));
  if (start === -1) return null;
  const body = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (stopMatches.some((re) => re.test(lines[i]))) break;
    body.push(lines[i]);
  }
  return body.join('\n').trim();
}

// LinkedIn commentary is plain text: markdown emphasis just shows up as literal asterisks.
function toPlainText(md) {
  return md
    .replace(/^\s*---\s*$/gm, '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/(^|[\s(])\*(?!\s)(.+?)(?<!\s)\*/g, '$1$2')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function render(url) {
  const lines = fs.readFileSync(DRAFT, 'utf8').split(/\r?\n/);
  const main = section(lines, /^##\s+Main post/i, [/^##\s+First comment/i]);
  const comment = section(lines, /^##\s+First comment/i, [/^##\s+/, /^---\s*$/]);
  if (!main) throw new Error('could not find the "## Main post" section in linkedin_post.md');
  const fill = (s) => (s || '').split(PLACEHOLDER).join(url || PLACEHOLDER);
  return { post: toPlainText(fill(main)), comment: toPlainText(fill(comment)) };
}

// ---------------------------------------------------------------- commands

async function whoami(token) {
  const res = await call('GET', `${API}/v2/userinfo`, token);
  if (!res.ok) return explainFailure('GET /v2/userinfo', res);
  const { sub, name } = res.json || {};
  console.log(`name: ${name || '(not returned)'}`);
  console.log(`LINKEDIN_AUTHOR_URN=urn:li:person:${sub}`);
  console.log('\nSet that as an env var, or just let the script resolve it from the token.');
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) return usage();

  const { token, from } = readToken();
  if (!token) {
    console.error(`No token. Set LINKEDIN_ACCESS_TOKEN, or write it to ${path.relative(ROOT, TOKEN_FILE)}.`);
    console.error('That file is gitignored — never paste a token into chat or a commit.');
    process.exitCode = 1;
    return;
  }
  if (opts.whoami) return whoami(token);

  const { post, comment } = render(opts.url);
  const author = resolveAuthor();

  // Deliberately never prints any part of the token — only where it came from.
  console.log(`\ntoken:  ${token.length} chars, loaded from ${from}`);
  console.log(`author: ${author || '(resolved from the token at publish time)'}`);
  console.log(`api:    LinkedIn-Version ${VERSION}`);

  if (post.length > POST_LIMIT) {
    console.error(`\n✗ the post body is ${post.length} chars — over the ${POST_LIMIT} limit. Trim it, or move part of it into the first comment.`);
    process.exitCode = 1;
    return;
  }
  if (comment.length > COMMENT_LIMIT) {
    console.error(`\n✗ the first comment is ${comment.length} chars — over the ${COMMENT_LIMIT} limit.`);
    process.exitCode = 1;
    return;
  }
  if (!opts.url && comment.includes(PLACEHOLDER)) {
    console.log('\n! the comment still holds the [PASTE MEDIUM LINK] placeholder — pass --url <medium story URL> to fill it in.');
  }

  console.log(`\n──── post body (${post.length}/${POST_LIMIT} chars) ────\n${post}`);
  if (!opts.commentOnly) console.log(`\n──── first comment (${comment.length}/${COMMENT_LIMIT} chars) ────\n${comment}`);

  if (!opts.publish) {
    console.log('\n(dry run — nothing sent. Add --publish to post for real.)');
    return;
  }

  let me = author;
  if (!me) {
    const info = await call('GET', `${API}/v2/userinfo`, token);
    if (!info.ok) return explainFailure('GET /v2/userinfo', info);
    me = `urn:li:person:${info.json.sub}`;
    console.log(`\nresolved author: ${me}`);
  }

  // 1. the post
  let postUrn = opts.postUrn;
  if (!opts.commentOnly) {
    const body = {
      author: me,
      commentary: post,
      visibility: 'PUBLIC',
      distribution: { feedDistribution: 'MAIN_FEED', targetEntities: [], thirdPartyDistributionChannels: [] },
      lifecycleState: 'PUBLISHED',
      isReshareDisabledByAuthor: false,
    };
    const res = await call('POST', `${API}/rest/posts`, token, body);
    if (!res.ok) return explainFailure('POST /rest/posts', res);
    postUrn = res.id || (res.json && res.json.id);
    console.log(`\n✓ post published — ${postUrn || '(no x-restli-id header)'}`);
    if (!postUrn) {
      console.error('  No post URN returned, so the comment step cannot target it. Pass it later with --post-urn.');
      process.exitCode = 1;
      return;
    }
  }

  // 2. the first comment, on that post
  if (!postUrn) {
    console.log('\n! no --post-urn given, so the first comment was skipped.');
    process.exitCode = 1;
    return;
  }
  const res = await call('POST', `${API}/rest/socialActions/${encodeURIComponent(postUrn)}/comments`, token, {
    actor: me,
    object: postUrn,
    message: { text: comment },
  });
  if (!res.ok) return explainFailure('POST /rest/socialActions/{postUrn}/comments', res);
  console.log(`✓ first comment posted — id ${res.id || (res.json && res.json.id) || '(returned)'}`);
  console.log('\nNow: pin that comment, and stay in the replies for the first couple of hours.');
}

main().catch((err) => {
  console.error(`\n✗ ${err.message}`);
  process.exitCode = 1;
});
