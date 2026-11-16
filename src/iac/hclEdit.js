'use strict';

// Small, format-preserving editor for HCL source text.
//
// Patches are applied as text edits (not parse -> regenerate) so the diff a
// reviewer sees contains only the security change, with comments and layout
// intact. Nothing here is trusted for correctness: every result is re-parsed
// by the real HCL parser and re-checked by OPA before it can be accepted.

const IDENT = /[A-Za-z_][A-Za-z0-9_-]*/y;
const CLOSERS = { '{': '}', '[': ']', '(': ')' };

// i points at the opening quote. Handles escapes and ${ ... } templates,
// which may themselves contain quoted strings.
function skipString(src, i) {
  i += 1;
  while (i < src.length) {
    const ch = src[i];
    if (ch === '\\') i += 2;
    else if (ch === '"') return i + 1;
    else if ((ch === '$' || ch === '%') && src[i + 1] === '{') i = matchClose(src, i + 1) + 1;
    else i += 1;
  }
  return i;
}

// Returns the index just past a heredoc starting at i, or -1 if i is not one.
function skipHeredoc(src, i) {
  const m = /^<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n/.exec(src.slice(i, i + 120));
  if (!m) return -1;
  const terminator = new RegExp(`^[ \\t]*${m[1]}[ \\t]*$`, 'm');
  const bodyStart = i + m[0].length;
  const end = terminator.exec(src.slice(bodyStart));
  return end ? bodyStart + end.index + end[0].length : src.length;
}

function skipComment(src, i) {
  if (src[i] === '#' || (src[i] === '/' && src[i + 1] === '/')) {
    const nl = src.indexOf('\n', i);
    return nl === -1 ? src.length : nl;
  }
  if (src[i] === '/' && src[i + 1] === '*') {
    const end = src.indexOf('*/', i + 2);
    return end === -1 ? src.length : end + 2;
  }
  return -1;
}

// i points at an opening bracket; returns the index of its partner.
function matchClose(src, i) {
  const close = CLOSERS[src[i]];
  const open = src[i];
  let depth = 0;
  while (i < src.length) {
    const ch = src[i];
    const comment = skipComment(src, i);
    if (comment !== -1) {
      i = comment;
    } else if (ch === '"') {
      i = skipString(src, i);
    } else if (ch === '<' && src[i + 1] === '<' && skipHeredoc(src, i) !== -1) {
      i = skipHeredoc(src, i);
    } else {
      if (ch === open) depth += 1;
      else if (ch === close && --depth === 0) return i;
      i += 1;
    }
  }
  return src.length - 1;
}

// End of an attribute value: the first newline or comment outside any
// bracket, string or heredoc.
function expressionEnd(src, i, limit) {
  while (i < limit) {
    const ch = src[i];
    if (ch === '\n' || skipComment(src, i) !== -1) break;
    if (ch === '"') i = skipString(src, i);
    else if (ch === '<' && src[i + 1] === '<' && skipHeredoc(src, i) !== -1) return skipHeredoc(src, i);
    else if (CLOSERS[ch]) i = matchClose(src, i) + 1;
    else i += 1;
  }
  while (i > 0 && /[ \t\r]/.test(src[i - 1])) i -= 1;
  return i;
}

/** Lists the attributes and blocks directly inside src[start, end). */
function parseBody(src, start = 0, end = src.length) {
  const items = [];
  let i = start;
  while (i < end) {
    const comment = skipComment(src, i);
    if (comment !== -1) {
      i = comment;
      continue;
    }
    IDENT.lastIndex = i;
    const ident = IDENT.exec(src);
    if (!ident) {
      i += 1;
      continue;
    }
    const itemStart = i;
    i += ident[0].length;
    while (/[ \t]/.test(src[i])) i += 1;

    if (src[i] === '=' && src[i + 1] !== '=') {
      i += 1;
      while (/[ \t]/.test(src[i])) i += 1;
      const valueEnd = expressionEnd(src, i, end);
      items.push({ kind: 'attr', name: ident[0], start: itemStart, valueStart: i, end: valueEnd });
      i = valueEnd;
      continue;
    }

    const labels = [];
    while (src[i] === '"') {
      const close = skipString(src, i);
      labels.push(src.slice(i + 1, close - 1));
      i = close;
      while (/[ \t]/.test(src[i])) i += 1;
    }
    if (src[i] !== '{') continue;
    const close = matchClose(src, i);
    items.push({ kind: 'block', name: ident[0], labels, start: itemStart, bodyStart: i + 1, bodyEnd: close, end: close + 1 });
    i = close + 1;
  }
  return items;
}

const sameLabels = (a, b) => a.length === b.length && a.every((v, idx) => v === b[idx]);

function findBlock(src, name, labels) {
  return parseBody(src).find((it) => it.kind === 'block' && it.name === name && sameLabels(it.labels, labels));
}

function nestedBlocks(src, block, name) {
  return parseBody(src, block.bodyStart, block.bodyEnd).filter((it) => it.kind === 'block' && it.name === name);
}

function indentOf(src, index) {
  const lineStart = src.lastIndexOf('\n', index - 1) + 1;
  return /^[ \t]*/.exec(src.slice(lineStart, index))[0];
}

// Inserts text as the last line(s) of a block body, indented one level.
function appendToBlock(src, block, text) {
  const indent = `${indentOf(src, block.start)}  `;
  const body = text
    .split('\n')
    .map((line) => (line ? indent + line : line))
    .join('\n');
  const lineStart = src.lastIndexOf('\n', block.bodyEnd - 1) + 1;
  // A one-line block ("foo { }") has its brace on the header line.
  if (lineStart <= block.bodyStart) {
    return `${src.slice(0, block.bodyEnd).trimEnd()}\n${body}\n${indentOf(src, block.start)}${src.slice(block.bodyEnd)}`;
  }
  return `${src.slice(0, lineStart)}${body}\n${src.slice(lineStart)}`;
}

/** Sets `name = literal` inside a block, replacing an existing value. */
function setAttr(src, block, name, literal) {
  const attrs = parseBody(src, block.bodyStart, block.bodyEnd).filter((it) => it.kind === 'attr');
  const existing = attrs.find((it) => it.name === name);
  if (existing) return src.slice(0, existing.valueStart) + literal + src.slice(existing.end);

  // Line the new '=' up with the attribute above it, as `terraform fmt` would.
  const last = attrs[attrs.length - 1];
  const column = last ? src.slice(last.start, last.valueStart).indexOf('=') : 0;
  return appendToBlock(src, block, `${name.padEnd(column - 1)} = ${literal}`);
}

module.exports = { parseBody, findBlock, nestedBlocks, setAttr, appendToBlock };
