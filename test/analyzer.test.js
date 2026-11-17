'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyze } = require('../index');

function oauthScheme(scopes) {
  return {
    type: 'oauth2',
    flows: {
      authorizationCode: {
        authorizationUrl: 'https://auth.example.com/authorize',
        tokenUrl: 'https://auth.example.com/token',
        scopes,
      },
    },
  };
}

function baseSpec(overrides = {}) {
  return {
    openapi: '3.0.3',
    info: { title: 'demo', version: '1.0.0' },
    components: {
      securitySchemes: {
        oauth: oauthScheme({ read: 'read access', write: 'write access', Read: 'typo variant' }),
        apiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
      },
    },
    paths: {},
    ...overrides,
  };
}

function ruleIds(report, path, method) {
  return report.findings
    .filter((f) => f.path === path && f.method === method)
    .map((f) => f.ruleId);
}

test('全局 security 被继承，operation 级覆盖全局', () => {
  const spec = baseSpec({
    security: [{ oauth: ['read'] }],
    paths: {
      '/status': {
        get: { operationId: 'status', responses: { 200: { description: 'ok' } } },
      },
      '/metrics': {
        get: {
          operationId: 'metrics',
          security: [{ apiKey: [] }],
          responses: { 200: { description: 'ok' } },
        },
      },
    },
  });
  const report = analyze(spec);
  assert.deepEqual(ruleIds(report, '/status', 'get'), []);
  assert.deepEqual(ruleIds(report, '/metrics', 'get'), []);
  assert.equal(report.summary.anonymous, 0);
});

test('显式 security: [] 覆盖全局并视为公开接口，必须在允许清单且有理由', () => {
  const spec = baseSpec({
    security: [{ oauth: ['read'] }],
    paths: {
      '/health': {
        get: {
          operationId: 'health',
          security: [],
          responses: { 200: { description: 'ok' } },
        },
      },
    },
  });

  const unlisted = analyze(spec);
  assert.deepEqual(ruleIds(unlisted, '/health', 'get'), ['unlisted-public-endpoint']);

  const noReason = analyze(spec, { allowlist: [{ path: '/health', method: 'get' }] });
  assert.deepEqual(ruleIds(noReason, '/health', 'get'), ['allowlist-missing-reason']);

  const listed = analyze(spec, {
    allowlist: [{ path: '/health', method: 'GET', reason: '负载均衡探活，无业务数据' }],
  });
  assert.deepEqual(ruleIds(listed, '/health', 'get'), []);
  assert.equal(listed.summary.anonymous, 1);
});

test('写接口只要求只读 scope 时报告作用域扩大，要求写 scope 则通过', () => {
  const spec = baseSpec({
    paths: {
      '/users': {
        get: {
          operationId: 'listUsers',
          security: [{ oauth: ['read'] }],
          responses: { 200: { description: 'ok' } },
        },
        post: {
          operationId: 'createUser',
          security: [{ oauth: ['read'] }],
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { name: { type: 'string' } },
                },
              },
            },
          },
          responses: { 201: { description: 'created' } },
        },
      },
    },
  });
  const report = analyze(spec);
  assert.deepEqual(ruleIds(report, '/users', 'get'), []);
  assert.ok(ruleIds(report, '/users', 'post').includes('scope-escalation'));

  const fixed = baseSpec({
    paths: {
      '/users': {
        post: {
          operationId: 'createUser',
          security: [{ oauth: ['write'] }],
          responses: { 201: { description: 'created' } },
        },
      },
    },
  });
  assert.deepEqual(ruleIds(analyze(fixed), '/users', 'post'), []);
});

test('敏感匿名写接口为 critical，允许清单过期条目给出提示', () => {
  const spec = baseSpec({
    paths: {
      '/admin/users': {
        delete: {
          operationId: 'deleteUser',
          responses: { 204: { description: 'deleted' } },
        },
      },
    },
  });
  const report = analyze(spec, {
    allowlist: [{ path: '/health', method: 'get', reason: 'probe' }],
  });
  const finding = report.findings.find((f) => f.ruleId === 'unlisted-public-endpoint');
  assert.equal(finding.severity, 'critical');
  assert.ok(ruleIds(report, '/health', 'get').includes('stale-allowlist-entry'));
});

test('未知安全方案、未定义 scope 与 scope 大小写敏感', () => {
  const spec = baseSpec({
    paths: {
      '/a': {
        get: {
          operationId: 'a',
          security: [{ ghost: [] }],
          responses: { 200: { description: 'ok' } },
        },
      },
      '/b': {
        get: {
          operationId: 'b',
          security: [{ oauth: ['READ'] }],
          responses: { 200: { description: 'ok' } },
        },
      },
      '/c': {
        get: {
          operationId: 'c',
          security: [{ oauth: ['read'] }],
          responses: { 200: { description: 'ok' } },
        },
      },
    },
  });
  const report = analyze(spec);
  assert.ok(ruleIds(report, '/a', 'get').includes('unknown-security-scheme'));
  assert.ok(ruleIds(report, '/a', 'get').includes('missing-authentication'));

  const caseFinding = report.findings.find(
    (f) => f.path === '/b' && f.ruleId === 'unknown-scope'
  );
  assert.ok(caseFinding, 'READ 与 read 大小写不同应判为未定义');
  assert.match(caseFinding.message, /大小写/);

  assert.deepEqual(ruleIds(report, '/c', 'get'), []);
});

test('AND/OR 语义：任一备选完整满足即可，对象内多方案为 AND', () => {
  const spec = baseSpec({
    paths: {
      '/or': {
        get: {
          operationId: 'or',
          security: [{ ghost: [] }, { apiKey: [] }],
          responses: { 200: { description: 'ok' } },
        },
      },
      '/and': {
        get: {
          operationId: 'and',
          security: [{ apiKey: [], ghost: [] }],
          responses: { 200: { description: 'ok' } },
        },
      },
    },
  });
  const report = analyze(spec);
  // OR：apiKey 备选有效，不视为匿名
  assert.ok(!ruleIds(report, '/or', 'get').includes('missing-authentication'));
  assert.ok(ruleIds(report, '/or', 'get').includes('unknown-security-scheme'));
  // AND：同一对象内 ghost 无法解析，唯一备选失效
  assert.ok(ruleIds(report, '/and', 'get').includes('missing-authentication'));
});

test('$ref 解析：参数、请求体、安全方案', () => {
  const spec = baseSpec({
    components: {
      securitySchemes: {
        oauth: oauthScheme({ read: 'r', write: 'w' }),
        keyRef: { $ref: '#/components/securitySchemes/apiKey' },
        apiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
      },
      parameters: {
        LimitParam: {
          name: 'limit',
          in: 'query',
          schema: { type: 'integer', minimum: 1 },
        },
        BrokenParam: { name: 'broken', in: 'query' },
      },
      schemas: {
        CreatePayload: {
          type: 'object',
          properties: {
            password: { type: 'string' },
            nickname: {},
          },
        },
      },
      requestBodies: {
        CreateBody: {
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreatePayload' },
            },
          },
        },
      },
    },
    paths: {
      '/items': {
        post: {
          operationId: 'createItem',
          security: [{ keyRef: ['write'] }],
          parameters: [
            { $ref: '#/components/parameters/LimitParam' },
            { $ref: '#/components/parameters/BrokenParam' },
          ],
          requestBody: { $ref: '#/components/requestBodies/CreateBody' },
          responses: { 201: { description: 'created' } },
        },
      },
    },
  });
  const rules = ruleIds(analyze(spec), '/items', 'post');
  assert.ok(rules.includes('missing-parameter-schema'), 'broken 参数缺 schema');
  assert.ok(rules.includes('unvalidated-request-field'), 'nickname 未声明类型');
  assert.ok(rules.includes('sensitive-field-unconstrained'), 'password 缺约束');
  assert.ok(!rules.includes('unknown-security-scheme'), '$ref 方案应可解析');
});

test('重复 operationId 报错并保留两个位置', () => {
  const spec = baseSpec({
    security: [{ apiKey: [] }],
    paths: {
      '/x': { get: { operationId: 'dup', responses: { 200: { description: 'ok' } } } },
      '/y': { get: { operationId: 'dup', responses: { 200: { description: 'ok' } } } },
    },
  });
  const report = analyze(spec);
  const dup = report.findings.find((f) => f.ruleId === 'duplicate-operation-id');
  assert.ok(dup);
  assert.match(dup.message, /GET \/x/);
  assert.match(dup.message, /GET \/y/);
});

test('响应包含敏感字段时匿名只读接口升级为 high', () => {
  const spec = baseSpec({
    paths: {
      '/profile': {
        get: {
          operationId: 'profile',
          responses: {
            200: {
              description: 'ok',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: { email: { type: 'string', format: 'email' } },
                  },
                },
              },
            },
          },
        },
      },
    },
  });
  const finding = analyze(spec).findings.find(
    (f) => f.ruleId === 'unlisted-public-endpoint'
  );
  assert.equal(finding.severity, 'high');
});

test('非法输入抛出 TypeError', () => {
  assert.throws(() => analyze(null), TypeError);
  assert.throws(() => analyze('nope'), TypeError);
});
