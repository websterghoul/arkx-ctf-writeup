// Builds a .docx from report/full_report.html (same single source of content as
// the PDF). No external libraries: emits OOXML directly and zips the package.
//
// usage: node report/tools/build_docx.js
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const REPORT_DIR = path.join(__dirname, '..');
const HTML = path.join(REPORT_DIR, 'full_report.html');
const OUT = path.join(REPORT_DIR, 'AI_Agent_MCP_Security_Verified_Vulnerability_Report.docx');
const BUILD = path.join(REPORT_DIR, '..', '.work', 'docx-build');

const VOID = new Set(['img', 'br', 'hr', 'meta', 'link', 'input']);
const escXml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
// The HTML source carries entities; they must be decoded before the text is
// re-escaped for OOXML, otherwise Word shows the literal entity.
const ENT = {
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&#39;': "'",
  '&nbsp;': '\u00a0',
  '&mdash;': '\u2014',
  '&ndash;': '\u2013',
  '&ldquo;': '\u201c',
  '&rdquo;': '\u201d',
  '&lsquo;': '\u2018',
  '&rsquo;': '\u2019',
  '&hellip;': '\u2026',
  '&rarr;': '\u2192',
};
const decode = (s) => String(s).replace(/&[a-zA-Z#0-9]{1,8};/g, (e) => (ENT[e] !== undefined ? ENT[e] : e));

/* ------------------------------------------------------------- tiny parser */
function parse(html) {
  const root = { tag: 'root', attrs: {}, children: [] };
  const stack = [root];
  const re = /<(\/?)([a-zA-Z0-9]+)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>|([^<]+)/g;
  let m;
  while ((m = re.exec(html))) {
    if (m[5] !== undefined) {
      const text = decode(m[5]);
      if (text.trim() || / /.test(text)) stack[stack.length - 1].children.push({ text });
      continue;
    }
    const [, closing, tag, attrStr, selfClose] = m;
    if (closing) {
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].tag === tag) {
          stack.length = i;
          break;
        }
      }
      continue;
    }
    const attrs = {};
    const ar = /([a-zA-Z-]+)\s*=\s*"([^"]*)"/g;
    let a;
    while ((a = ar.exec(attrStr))) attrs[a[1]] = a[2];
    const node = { tag, attrs, children: [] };
    stack[stack.length - 1].children.push(node);
    if (!VOID.has(tag) && !selfClose) stack.push(node);
  }
  return root;
}

/* ------------------------------------------------------------ xml emitters */
const run = (text, opts = {}) => {
  if (text === '') return '';
  const rpr =
    (opts.b ? '<w:b/>' : '') +
    (opts.i ? '<w:i/>' : '') +
    (opts.mono ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="17"/>' : '') +
    (opts.small ? '<w:sz w:val="17"/>' : '');
  const parts = String(text).split('\n');
  return parts
    .map((p, i) => `<w:r>${rpr ? `<w:rPr>${rpr}</w:rPr>` : ''}${i ? '<w:br/>' : ''}<w:t xml:space="preserve">${escXml(p)}</w:t></w:r>`)
    .join('');
};

function inlineRuns(node, opts = {}) {
  let out = '';
  for (const c of node.children || []) {
    if (c.text !== undefined) {
      out += run(c.text, opts);
      continue;
    }
    const o = { ...opts };
    if (c.tag === 'b' || c.tag === 'strong' || c.tag === 'th') o.b = true;
    if (c.tag === 'i' || c.tag === 'em') o.i = true;
    if (c.tag === 'code') o.mono = true;
    if (c.tag === 'br') {
      out += '<w:r><w:br/></w:r>';
      continue;
    }
    out += inlineRuns(c, o);
  }
  return out;
}

const para = (style, contents, extra = '') =>
  `<w:p>${style ? `<w:pPr><w:pStyle w:val="${style}"/>${extra}</w:pPr>` : extra ? `<w:pPr>${extra}</w:pPr>` : ''}${contents}</w:p>`;

/* ----------------------------------------------------------------- images */
const MEDIA = [];
let imageSeq = 0;
function imagePng(relPath) {
  const abs = path.join(REPORT_DIR, relPath);
  const buf = fs.readFileSync(abs);
  const w = buf.readUInt32BE(16);
  const h = buf.readUInt32BE(20);
  const name = `image${++imageSeq}.png`;
  MEDIA.push({ name, buf });
  // Fit inside a 16cm x 22cm box, preserving aspect ratio.
  const MAXW = 5_760_000;
  const MAXH = 7_920_000;
  let cx = MAXW;
  let cy = Math.round((h / w) * MAXW);
  if (cy > MAXH) {
    cy = MAXH;
    cx = Math.round((w / h) * MAXH);
  }
  const rid = `rIdImg${imageSeq}`;
  return {
    rid,
    xml: `<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">
<wp:extent cx="${cx}" cy="${cy}"/><wp:docPr id="${imageSeq}" name="${name}"/>
<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:nvPicPr><pic:cNvPr id="${imageSeq}" name="${name}"/><pic:cNvPicPr/></pic:nvPicPr>
<pic:blipFill><a:blip r:embed="${rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="${cx}" cy="${cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`,
  };
}

/* ---------------------------------------------------------------- rendering */
const BLOCKY = new Set(['p', 'ul', 'ol', 'li', 'pre', 'table', 'h1', 'h2', 'h3', 'figure', 'figcaption']);
const hasBlock = (n) => (n.children || []).some((c) => c.tag && BLOCKY.has(c.tag));
let lastImg = null;
function blocks(node, out) {
  for (const c of node.children || []) {
    if (c.text !== undefined) {
      if (c.text.replace(/\s+/g, '') !== '') out.push(para('Normal', run(c.text.trim())));
      continue;
    }
    const style = { h1: 'Heading1', h2: 'Heading2', h3: 'Heading3' }[c.tag];
    if (style) {
      out.push(para(style, inlineRuns(c)));
      continue;
    }
    if (c.tag === 'p') {
      const t = inlineRuns(c).trim();
      if (t) out.push(para('Normal', t));
      continue;
    }
    if (c.tag === 'pre') {
      out.push(para('Code', inlineRuns(c, { mono: true })));
      continue;
    }
    if (c.tag === 'li') {
      out.push(para('ListParagraph', run('•  ') + inlineRuns(c), '<w:ind w:left="360"/>'));
      continue;
    }
    if (c.tag === 'figcaption') {
      out.push(para('Caption', inlineRuns(c, { small: true, i: true })));
      continue;
    }
    if (c.tag === 'img') {
      const src = c.attrs.src || '';
      if (src && src !== lastImg) {
        lastImg = src;
        out.push(imagePng(src).xml);
      }
      continue;
    }
    if (c.tag === 'table') {
      out.push(tableXml(c));
      continue;
    }
    if (c.tag === 'th' || c.tag === 'td') {
      // Table cells: a plain cell becomes one paragraph (bold when it is a
      // header); a cell holding block content is descended into.
      if (hasBlock(c)) blocks(c, out);
      else {
        const t = inlineRuns(c, c.tag === 'th' ? { b: true } : {}).trim();
        if (t) out.push(para('Normal', t));
      }
      continue;
    }
    // wrappers and anything else: descend
    blocks(c, out);
  }
}

function tableXml(node) {
  const rows = [];
  const collectRows = (n) => {
    for (const c of n.children || []) {
      if (c.text !== undefined) continue;
      if (c.tag === 'tr') rows.push(c);
      else collectRows(c);
    }
  };
  collectRows(node);
  const body = rows
    .map((tr) => {
      const cells = (tr.children || []).filter((c) => c.tag === 'td' || c.tag === 'th');
      return `<w:tr>${cells
        .map((cell) => {
          const inner = [];
          blocks(cell, inner);
          const content = inner.join('') || '<w:p/>';
          return `<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>${content}</w:tc>`;
        })
        .join('')}</w:tr>`;
    })
    .join('');
  return `<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>
<w:top w:val="single" w:sz="4" w:color="B9BEC7"/><w:left w:val="single" w:sz="4" w:color="B9BEC7"/>
<w:bottom w:val="single" w:sz="4" w:color="B9BEC7"/><w:right w:val="single" w:sz="4" w:color="B9BEC7"/>
<w:insideH w:val="single" w:sz="4" w:color="CCD1D8"/><w:insideV w:val="single" w:sz="4" w:color="CCD1D8"/>
</w:tblBorders></w:tblPr>${body}</w:tbl><w:p/>`;
}

/* ------------------------------------------------------------------ package */
const html = fs.readFileSync(HTML, 'utf8');
const bodyMatch = html.match(/<body>([\s\S]*)<\/body>/);
if (!bodyMatch) throw new Error('no <body> found');

// Drop non-content wrappers (the cover is kept; scripts/styles are not present).
const body = bodyMatch[1].replace(/<!--[\s\S]*?-->/g, '');
const tree = parse(body);
const out = [];
let imgState = { reset: true };
blocks(tree, out);
const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
 xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
<w:body>${out.join('')}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="567" w:right="567" w:bottom="567" w:left="567"/></w:sectPr></w:body></w:document>`;

const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="21"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="80" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="320" w:after="160"/><w:outlineLvl w:val="0"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="40"/><w:color w:val="16181D"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="280" w:after="120"/><w:outlineLvl w:val="1"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0B3B6F"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="0B3B6F"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:after="80"/><w:shd w:val="clear" w:fill="F7F8FA"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="17"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="Caption"/><w:basedOn w:val="Normal"/>
<w:rPr><w:i/><w:sz w:val="18"/><w:color w:val="444444"/></w:rPr></w:style>
</w:styles>`;

const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>`;

const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>`;

const docRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
${MEDIA.map(
  (m) =>
    `<Relationship Id="rIdImg${Number(m.name.replace(/\D/g, ''))}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/${m.name}"/>`
).join('\n')}
</Relationships>`;

const coreXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>AI Agent &amp; MCP Security — Verified Vulnerability Report</dc:title>
<dc:creator>ARKX CTF engagement</dc:creator>
<dcterms:created xsi:type="dcterms:W3CDTF">2026-10-14T00:00:00Z</dcterms:created>
</cp:coreProperties>`;

const appXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
<Application>build_docx.js</Application><AppVersion>1.0</AppVersion></Properties>`;

/* --------------------------------------------------------------------- write */
fs.rmSync(BUILD, { recursive: true, force: true });
fs.mkdirSync(path.join(BUILD, '_rels'), { recursive: true });
fs.mkdirSync(path.join(BUILD, 'word', '_rels'), { recursive: true });
fs.mkdirSync(path.join(BUILD, 'word', 'media'), { recursive: true });
fs.mkdirSync(path.join(BUILD, 'docProps'), { recursive: true });

fs.writeFileSync(path.join(BUILD, '[Content_Types].xml'), contentTypes);
fs.writeFileSync(path.join(BUILD, '_rels', '.rels'), rootRels);
fs.writeFileSync(path.join(BUILD, 'word', 'document.xml'), documentXml);
fs.writeFileSync(path.join(BUILD, 'word', 'styles.xml'), stylesXml);
fs.writeFileSync(path.join(BUILD, 'word', '_rels', 'document.xml.rels'), docRels);
fs.writeFileSync(path.join(BUILD, 'docProps', 'core.xml'), coreXml);
fs.writeFileSync(path.join(BUILD, 'docProps', 'app.xml'), appXml);
for (const m of MEDIA) fs.writeFileSync(path.join(BUILD, 'word', 'media', m.name), m.buf);

fs.rmSync(OUT, { force: true });
execFileSync('zip', ['-r', '-X', '-q', OUT, '[Content_Types].xml', '_rels', 'word', 'docProps'], { cwd: BUILD });

const kb = (fs.statSync(OUT).size / 1024).toFixed(0);
console.log(`wrote ${OUT} (${kb} KB, ${MEDIA.length} images, ${out.length} blocks)`);
