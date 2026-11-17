'use strict';

const { resolveRef } = require('./ref');
const {
  isSensitivePath,
  isSensitiveField,
  hasConstraints,
  isTyped,
  collectFields,
  jsonBodySchema,
} = require('./sensitivity');
const {
  WRITE_METHODS,
  scopeTier,
  definedScopes,
  isScopeCarryingScheme,
  effectiveSecurity,
} = require('./security');

const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function normalizeAllowlist(entries) {
  return entries.map((entry) => ({
    path: entry.path,
    method: entry.method ? String(entry.method).toLowerCase() : '*',
    reason: typeof entry.reason === 'string' ? entry.reason.trim() : '',
  }));
}

function matchAllowlist(allowlist, path, method) {
  return allowlist.find(
    (entry) =>
      entry.path === path && (entry.method === '*' || entry.method === method)
  );
}

function anonymousSeverity({ sensitive, isWrite }) {
  if (sensitive && isWrite) return 'critical';
  if (sensitive) return 'high';
  if (isWrite) return 'medium';
  return 'low';
}

function mergeParameters(root, pathItem, operation) {
  const merged = new Map();
  const addAll = (params) => {
    for (const raw of params || []) {
      const param = resolveRef(root, raw);
      if (param && param.name) {
        merged.set(`${param.in}:${param.name}`, param);
      }
    }
  };
  addAll(pathItem.parameters);
  addAll(operation.parameters);
  return [...merged.values()];
}

function collectResponseFields(root, operation) {
  const fields = [];
  const responses = operation.responses || {};
  for (const [status, rawResponse] of Object.entries(responses)) {
    if (!/^2/.test(status) && status !== 'default') continue;
    const response = resolveRef(root, rawResponse);
    const schema = jsonBodySchema(root, response);
    for (const field of collectFields(root, schema)) {
      fields.push(field);
    }
  }
  return fields;
}

function analyzeOperation(root, ctx) {
  const { path, method, operation, pathItem, allowlist, findings } = ctx;
  const isWrite = WRITE_METHODS.has(method);
  const location = `${method.toUpperCase()} ${path}`;

  const add = (ruleId, severity, message, extra = {}) => {
    findings.push({ ruleId, severity, path, method, operationId: operation.operationId, message, ...extra });
  };

  // ---- 敏感度：路径 + 请求体字段 + 响应字段 ----
  const requestBody = resolveRef(root, operation.requestBody);
  const requestSchema = jsonBodySchema(root, requestBody);
  const requestFields = collectFields(root, requestSchema);
  const responseFields = collectResponseFields(root, operation);
  const sensitive =
    isSensitivePath(path) ||
    requestFields.some((f) => isSensitiveField(f.name)) ||
    responseFields.some((f) => isSensitiveField(f.name));

  // ---- 有效安全要求（operation 覆盖全局，[] 表示匿名）----
  const security = effectiveSecurity(operation, root);
  const schemes = (root.components && root.components.securitySchemes) || {};

  if (security.length === 0) {
    const entry = matchAllowlist(allowlist, path, method);
    if (!entry) {
      add(
        'unlisted-public-endpoint',
        anonymousSeverity({ sensitive, isWrite }),
        `${location} 无有效安全要求（匿名可访问），且不在公开接口允许清单中`,
        { sensitive }
      );
    } else if (!entry.reason) {
      add(
        'allowlist-missing-reason',
        'medium',
        `${location} 在允许清单中但缺少公开理由`
      );
    }
    return { anonymous: true, sensitive };
  }

  // ---- 评估 OR 备选：任一 requirement 全部满足即视为已认证 ----
  const alternatives = [];
  for (const requirement of security) {
    if (!requirement || typeof requirement !== 'object') continue;
    const entries = Object.entries(requirement);
    if (entries.length === 0) continue;
    const resolved = entries.map(([name, scopes]) => ({
      name,
      scopes: Array.isArray(scopes) ? scopes : [],
      scheme: resolveRef(root, schemes[name]),
    }));
    alternatives.push(resolved);
  }

  const unknownSchemes = new Set();
  for (const alt of alternatives) {
    for (const req of alt) {
      if (!req.scheme) unknownSchemes.add(req.name);
    }
  }
  for (const name of unknownSchemes) {
    add(
      'unknown-security-scheme',
      'high',
      `${location} 引用了未在 components.securitySchemes 中定义的安全方案 "${name}"`
    );
  }

  const resolvable = alternatives.filter((alt) => alt.every((req) => req.scheme));
  if (resolvable.length === 0) {
    add(
      'missing-authentication',
      sensitive ? 'critical' : 'high',
      `${location} 没有任何一个可解析的安全备选，实际等同匿名访问`,
      { sensitive }
    );
    return { anonymous: true, sensitive };
  }

  // ---- scope 检查（oauth2 / openIdConnect）----
  for (const alt of resolvable) {
    for (const req of alt) {
      if (!isScopeCarryingScheme(req.scheme)) continue;
      const known = definedScopes(req.scheme);
      if (req.scopes.length === 0) {
        add(
          'missing-scope',
          isWrite || sensitive ? 'high' : 'medium',
          `${location} 使用方案 "${req.name}" 但未要求任何授权 scope`
        );
      }
      for (const scope of req.scopes) {
        if (known.size > 0 && !known.has(scope)) {
          const caseVariant = [...known].find((k) => k.toLowerCase() === scope.toLowerCase());
          add(
            'unknown-scope',
            'medium',
            `${location} 要求的 scope "${scope}" 未在方案 "${req.name}" 中定义` +
              (caseVariant ? `（注意大小写：已定义的是 "${caseVariant}"，scope 匹配大小写敏感）` : '')
          );
        }
      }
    }
  }

  // ---- 作用域扩大：写操作必须至少有一个备选要求写级 scope ----
  if (isWrite) {
    const adequate = resolvable.some((alt) =>
      alt.some(
        (req) =>
          isScopeCarryingScheme(req.scheme) &&
          req.scopes.some((s) => scopeTier(s) !== 'read')
      )
    );
    if (!adequate) {
      const readScopes = [
        ...new Set(
          resolvable.flatMap((alt) =>
            alt.flatMap((req) => req.scopes.filter((s) => scopeTier(s) === 'read'))
          )
        ),
      ];
      add(
        'scope-escalation',
        'high',
        `${location} 是写操作，但所有安全备选只要求只读 scope` +
          (readScopes.length ? `（${readScopes.join(', ')}）` : '') +
          '，存在作用域扩大风险',
        { sensitive }
      );
    }
  }

  // ---- 参数校验 ----
  for (const param of mergeParameters(root, pathItem, operation)) {
    const schema = param.schema ? resolveRef(root, param.schema) : undefined;
    if (!param.schema && !param.content) {
      add(
        'missing-parameter-schema',
        'medium',
        `${location} 参数 "${param.name}"（in: ${param.in}）缺少 schema，无法校验`
      );
    } else if (schema && !isTyped(schema)) {
      add(
        'missing-parameter-schema',
        'low',
        `${location} 参数 "${param.name}"（in: ${param.in}）的 schema 未声明类型`
      );
    }
  }

  for (const field of requestFields) {
    if (!isTyped(field.schema)) {
      add(
        'unvalidated-request-field',
        'low',
        `${location} 请求体字段 "${field.name}" 未声明类型，缺少校验`
      );
    } else if (isSensitiveField(field.name) && !hasConstraints(field.schema)) {
      add(
        'sensitive-field-unconstrained',
        'medium',
        `${location} 敏感请求字段 "${field.name}" 缺少 format/pattern/长度等约束`
      );
    }
  }

  return { anonymous: false, sensitive };
}

function analyze(spec, options = {}) {
  if (!spec || typeof spec !== 'object') {
    throw new TypeError('analyze(spec) 需要一个 OpenAPI 文档对象');
  }
  const findings = [];
  const operations = [];
  const allowlist = normalizeAllowlist(options.allowlist || []);
  const usedAllowlist = new Set();
  const seenOperationIds = new Map();

  for (const [path, rawPathItem] of Object.entries(spec.paths || {})) {
    const pathItem = resolveRef(spec, rawPathItem);
    if (!pathItem || typeof pathItem !== 'object') continue;
    for (const method of HTTP_METHODS) {
      const rawOperation = pathItem[method];
      if (!rawOperation || typeof rawOperation !== 'object') continue;
      const operation = resolveRef(spec, rawOperation) || rawOperation;

      if (operation.operationId !== undefined) {
        if (seenOperationIds.has(operation.operationId)) {
          findings.push({
            ruleId: 'duplicate-operation-id',
            severity: 'medium',
            path,
            method,
            operationId: operation.operationId,
            message: `operationId "${operation.operationId}" 重复：${seenOperationIds.get(operation.operationId)} 与 ${method.toUpperCase()} ${path}`,
          });
        } else {
          seenOperationIds.set(operation.operationId, `${method.toUpperCase()} ${path}`);
        }
      }

      const result = analyzeOperation(spec, {
        path,
        method,
        operation,
        pathItem,
        allowlist,
        findings,
      });
      if (result.anonymous && matchAllowlist(allowlist, path, method)) {
        usedAllowlist.add(matchAllowlist(allowlist, path, method));
      }
      operations.push({
        path,
        method,
        operationId: operation.operationId,
        anonymous: result.anonymous,
        sensitive: result.sensitive,
      });
    }
  }

  for (const entry of allowlist) {
    if (!usedAllowlist.has(entry)) {
      findings.push({
        ruleId: 'stale-allowlist-entry',
        severity: 'info',
        path: entry.path,
        method: entry.method,
        message: `允许清单条目 ${entry.method.toUpperCase()} ${entry.path} 未匹配任何匿名接口`,
      });
    }
  }

  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const finding of findings) bySeverity[finding.severity] += 1;

  return {
    findings,
    operations,
    summary: {
      operations: operations.length,
      anonymous: operations.filter((o) => o.anonymous).length,
      findings: findings.length,
      bySeverity,
    },
  };
}

module.exports = { analyze };
