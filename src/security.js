'use strict';

const WRITE_METHODS = new Set(['post', 'put', 'patch', 'delete']);

// scope 分层：名称判定大小写不敏感，但 scope 匹配本身是大小写敏感的。
function scopeTier(name) {
  const lowered = String(name).toLowerCase();
  if (/(admin|manage|write|create|update|delete|edit|modify)/.test(lowered)) {
    return 'write';
  }
  if (/(read|view|list|get)/.test(lowered)) {
    return 'read';
  }
  return 'other';
}

function definedScopes(scheme) {
  const scopes = new Set();
  const flows = scheme && scheme.flows;
  if (flows && typeof flows === 'object') {
    for (const flow of Object.values(flows)) {
      if (flow && typeof flow.scopes === 'object' && flow.scopes) {
        for (const name of Object.keys(flow.scopes)) {
          scopes.add(name);
        }
      }
    }
  }
  return scopes;
}

function isScopeCarryingScheme(scheme) {
  return Boolean(
    scheme && (scheme.type === 'oauth2' || scheme.type === 'openIdConnect')
  );
}

// 计算有效安全要求：operation 级覆盖全局；显式 [] 表示匿名公开。
function effectiveSecurity(operation, spec) {
  if (operation.security !== undefined) {
    return Array.isArray(operation.security) ? operation.security : [];
  }
  if (Array.isArray(spec.security)) {
    return spec.security;
  }
  return [];
}

module.exports = {
  WRITE_METHODS,
  scopeTier,
  definedScopes,
  isScopeCarryingScheme,
  effectiveSecurity,
};
