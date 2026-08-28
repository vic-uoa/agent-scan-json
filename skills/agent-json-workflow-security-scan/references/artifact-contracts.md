# Artifact Contracts

| 文件 | 用途 |
|---|---|
| `00-scan-manifest.json` | 输入哈希、模式和规则版本 |
| `01-workflow-ir.json` | 规范化节点、边、变量、工具与覆盖缺口 |
| `02-security-facts.json` | 确定性证据 |
| `03-semantic-inventory.json` | 入口、资产、边界、能力、逐节点审核维度与契约覆盖率 |
| `04-rule-candidates.json` | 聚合前原始匹配与候选 |
| `05-test-cluster.json` | 正例、反例、边界、变形和规则定向输入 |
| `06-model-advisory.json` | 模型顾问边界、接受/拒绝的惰性建议和非权威措辞 |
| `07-verification.json` | 引用、聚合、输入簇和产物校验 |
| `08-findings.json` | 权威风险项 |
| `09-attack-surface.json` | 入口、资产、能力和攻击路径 |
| `10-dynamic-test-plan.json` | 默认禁止执行的沙盒交接计划 |
| `11-quality-gate.json` | 风险 PASS/REVIEW/FAIL、扫描完整性、阻断项与覆盖缺口分类 |
| `12-artifact-index.json` | 产物 SHA-256 与大小 |
| `report.json`、`report.md` | 机器和人工报告 |

每个 JSON 包含 `schema_version`、`scan_id`、`producer`、`producer_version`、`workflow_hash` 和 `created_at`。

`report.md` 与 `attack-surface.md` 是中文优先的人工阅读层；栏目、标签、严重度、状态、门禁和控制域应本地化，规则编号、节点 ID 和必要技术术语保持原值。所有 JSON 是稳定的机器接口层，字段名和 `CONFIRMED`、`OBSERVED`、`PASS`、`REVIEW`、`FAIL` 等枚举不得随报告语言变化。

`report.md` 先给出一页结论和最多三项优先处理事项，再分组展开证据。每条记录优先显示业务节点名、稳定节点 ID、代表路径、JSON Pointer 和聚合实例，避免只给抽象规则标题。`11-quality-gate.json` 保留兼容字段 `result`，同时提供 `risk_gate_result`、`completeness_result`、`scanner_gap_ids` 和 `runtime_gap_ids`。

解析器拥有节点、字段、边、变量和位置事实；规则引擎独占 Finding、状态、严重度、置信度和门禁；确定性输入簇构建器拥有种子血缘和最低用例覆盖。模型只能通过 `schemas/model-advisory.schema.json` 提交附加惰性测试、复核问题和非权威措辞。未知引用、真实密钥、重复输入和 Finding/目标不匹配的建议会被拒绝。

测试用例只有在 Finding、目标节点和路径变体全部匹配时才能关联攻击路径。计划覆盖、路由可满足覆盖和真实执行覆盖必须分别报告。`10-dynamic-test-plan.json` 固定 `execution_authorized=false`。
