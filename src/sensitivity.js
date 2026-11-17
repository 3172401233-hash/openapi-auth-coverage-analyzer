'use strict';

const { resolveRef } = require('./ref');

const SENSITIVE_PATH_SEGMENTS = new Set([
  'admin', 'internal', 'user', 'users', 'account', 'accounts', 'payment',
  'payments', 'billing', 'token', 'tokens', 'auth', 'password', 'secret',
  'secrets', 'key', 'keys', 'credential', 'credentials', 'private',
]);

const SENSITIVE_FIELD_NAMES = new Set([
  'password', 'passwd', 'secret', 'token', 'accesstoken', 'refreshtoken',
  'apikey', 'privatekey', 'ssn', 'creditcard', 'cardnumber', 'cvv',
  'email', 'phone', 'address', 'dob', 'idcard', 'bankaccount',
]);

function isSensitivePath(path) {
  return path
    .toLowerCase()
    .split('/')
    .filter(Boolean)
    .some((segment) => SENSITIVE_PATH_SEGMENTS.has(segment.replace(/[{}]/g, '')));
}

function isSensitiveField(name) {
  return SENSITIVE_FIELD_NAMES.has(String(name).toLowerCase().replace(/[_-]/g, ''));
}

function hasConstraints(schema) {
  return Boolean(
    schema &&
      (schema.minLength !== undefined ||
        schema.maxLength !== undefined ||
        schema.pattern !== undefined ||
        schema.format !== undefined ||
        schema.enum !== undefined)
  );
}

function isTyped(schema) {
  return Boolean(
    schema &&
      (schema.type !== undefined ||
        schema.oneOf || schema.anyOf || schema.allOf ||
        schema.enum || schema.const !== undefined)
  );
}

// 收集对象 schema 的顶层字段：[{ name, schema }]
function collectFields(root, schema) {
  const resolved = resolveRef(root, schema);
  if (!resolved || typeof resolved !== 'object') {
    return [];
  }
  const properties = resolved.properties;
  if (!properties || typeof properties !== 'object') {
    return [];
  }
  return Object.entries(properties).map(([name, propSchema]) => ({
    name,
    schema: resolveRef(root, propSchema),
  }));
}

function jsonBodySchema(root, body) {
  if (!body || typeof body !== 'object') return undefined;
  const content = body.content;
  if (!content || typeof content !== 'object') return undefined;
  const media = content['application/json'] || Object.values(content)[0];
  if (!media || !media.schema) return undefined;
  return resolveRef(root, media.schema);
}

module.exports = {
  isSensitivePath,
  isSensitiveField,
  hasConstraints,
  isTyped,
  collectFields,
  jsonBodySchema,
};
