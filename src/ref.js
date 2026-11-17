'use strict';

function unescapeSegment(segment) {
  return segment.replace(/~1/g, '/').replace(/~0/g, '~');
}

function resolvePointer(root, pointer) {
  if (typeof pointer !== 'string' || !pointer.startsWith('#/')) {
    return undefined;
  }
  let node = root;
  for (const raw of pointer.slice(2).split('/')) {
    const key = unescapeSegment(raw);
    if (node === null || typeof node !== 'object' || !(key in node)) {
      return undefined;
    }
    node = node[key];
  }
  return node;
}

// 解析本地 $ref 链，带循环保护；无法解析时返回 undefined。
function resolveRef(root, node, seen = new Set()) {
  let current = node;
  while (current && typeof current === 'object' && typeof current.$ref === 'string') {
    if (seen.has(current.$ref)) {
      return undefined;
    }
    seen.add(current.$ref);
    const target = resolvePointer(root, current.$ref);
    if (target === undefined) {
      return undefined;
    }
    current = target;
  }
  return current;
}

module.exports = { resolveRef, resolvePointer };
