# openapi-auth-coverage-analyzer

JavaScript OpenAPI 鉴权覆盖分析库：合并全局与 operation 级安全要求，结合路径、方法、
请求体字段和响应敏感度，判断接口是否具备认证、授权 scope 和必要参数校验。

## 用法

```js
const { analyze } = require('openapi-auth-coverage-analyzer');

const report = analyze(spec, {
  allowlist: [
    // 显式公开（security: []）的接口必须出现在允许清单并给出理由
    { path: '/health', method: 'get', reason: '负载均衡探活，无业务数据' },
  ],
});
// report.findings / report.operations / report.summary
```

运行测试：`node --test`

## 判定模型

- **有效安全要求**：operation 级 `security` 覆盖全局 `security`；显式 `security: []`
  表示匿名公开，必须命中允许清单且附带非空理由。
- **AND/OR 语义**：`security` 数组元素之间是 OR（任一备选完整满足即已认证），
  单个对象内的多个方案是 AND（全部可解析才有效）。
- **$ref**：参数、请求体、响应、安全方案均先解析本地 `$ref`（含循环保护）再判定。
- **scope 大小写**：required scope 与方案中定义的 scope 按 OAuth2 规范做大小写敏感
  匹配；仅大小写不同的会在报告中提示。scope 分层（read/write）判定大小写不敏感。
- **敏感度**：路径段（admin、users、payment…）、请求/响应字段名
  （password、token、email…）命中即视为敏感，用于提升风险等级。

## 风险分级规则

| 规则 | 等级 | 说明 |
| --- | --- | --- |
| `unlisted-public-endpoint` | critical / high / medium / low | 匿名接口未在允许清单。敏感写接口 critical，敏感读接口 high，普通写接口 medium，其余 low |
| `missing-authentication` | critical / high | 所有安全备选均无法解析，等同匿名。敏感接口 critical，其余 high |
| `scope-escalation` | high | 写操作的所有备选只要求只读 scope，存在作用域扩大风险 |
| `unknown-security-scheme` | high | 引用了未在 `components.securitySchemes` 定义的方案 |
| `missing-scope` | high / medium | oauth2/openIdConnect 未要求任何 scope；写或敏感接口为 high |
| `allowlist-missing-reason` | medium | 允许清单条目缺少公开理由 |
| `unknown-scope` | medium | 要求的 scope 未在方案 flows 中定义（大小写敏感） |
| `duplicate-operation-id` | medium | 同一 operationId 出现在多个操作中 |
| `sensitive-field-unconstrained` | medium | 敏感请求字段缺少 format/pattern/长度约束 |
| `missing-parameter-schema` | medium / low | 参数缺少 schema，或 schema 未声明类型 |
| `unvalidated-request-field` | low | 请求体字段未声明类型，缺少校验 |
| `stale-allowlist-entry` | info | 允许清单条目未匹配任何匿名接口 |

## 目录结构

- `src/analyzer.js` — 分析主流程与报告汇总
- `src/security.js` — 安全要求合并、scope 分层与匹配
- `src/sensitivity.js` — 路径/字段敏感度与 schema 校验辅助
- `src/ref.js` — 本地 `$ref` 解析
- `test/analyzer.test.js` — `node --test` 测试
