# Rule Catalog

## 规则模型

规则结论必须通过四个门：相关能力、可达数据或控制路径、缺少匹配的确定性控制、存在合理影响。关键词仅用于候选能力分类，不能单独确认漏洞。

报告分组是规则适用性的一部分：

- `risk`：存在与安全影响相关的静态事实或路径，进入风险计数和门禁。
- `posture`：JSON 比其他导出格式多提供的配置事实，例如明文 HTTP 端点；单独展示，不与跨方言基线风险比较。
- `hardening`：输入长度等纵深防御建议，在没有危险下游或资源放大路径时不称为漏洞。
- `coverage_gap`：运行时事实不可见。只记录一次合理缺口，不得按每个节点机械复制，也不进入风险数量。

当前目录包含 54 条规则。数量不是准确率指标；规则只有在节点类型、字段契约、数据/控制路径和证据状态满足时才适用。逐节点审核面见 [node-review-matrix.md](node-review-matrix.md)。

主控制基线为 [OWASP AISVS 1.0](https://owasp.org/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/)；风险映射使用 [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)、[OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)、[MITRE ATLAS](https://atlas.mitre.org/)、[OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) 和 CWE。NIST AI 100-2 用于术语与威胁分类，不作为单字段漏洞判据。

截至 2026-08，OWASP 事故映射仍使用 LLM Top 10 2025，而 Agentic Top 10 使用 2026 版。因此规则 ID 分别写作 `LLMxx:2025` 和 `ASIxx:2026`，不虚构 `LLMxx:2026` 版本。AISVS 的 `C2/C5/...` 是章节级映射；在没有逐项验证上下文时，不冒充具体要求已满足或已违反。

## 规则族

- `FLOW`：图完整性、引用、绕过、跨节点攻击链、循环和 Agent 失控。
- `IN`：输入 Schema、边界、文件、敏感字段与直接注入面。
- `LLM`：指令边界、Prompt 泄露、结构化输出、预算和回退。
- `TOOL`：参数控制、SSRF、代码执行、身份权限、输出、超时、供应链和动作门。
- `OUT`：输出契约、披露、中间输出、富文本与引用。
- `KB`：数据集范围、租户隔离、间接注入、来源和检索边界。

本轮新增的 `FLOW-017` 检查跨节点显式类型冲突，`TOOL-013` 检查 Python 明确返回类型与 CODE 节点声明契约冲突。两者在普通局部路径默认为 JSON 配置观察；只有进入机器消费、副作用或高影响后果时才进入风险组。

普通只读 RAG 只有在知识内容进入模型 Prompt 时作为低等级指令边界证据，并与同一模型的用户输入边界聚合；只有继续到达副作用能力、高影响决策或明确高信任输出时才升级为独立攻击链。固定单数据集不因 DSL 未携带运行时 ACL 而逐节点报警。来源传播关闭只有在业务或输出契约明确要求引用时才形成 Finding。

新增或未来字段不能靠关键词直接提升为 `CONFIRMED`。解析器先产生 `unmapped_node_field`；确认平台语义、加入字段契约和正反例之后，规则才可消费该字段。

可执行元数据位于 `rules/core-rules.yml`，平台字段绑定位于 `rules/json-dsl-bindings.yml`，适用性与排除策略位于 `rules/rule-applicability.yml`。每条规则必须恰好有一个字段绑定和一个适用性策略。路径与影响判定规则见 [applicability-model.md](applicability-model.md)。

## 新增规则

1. 在目录中加入规则元数据与标准映射。
2. 在绑定表中声明原始节点类型、DSL 字段和运行时上下文。
3. 在适用性表中声明路径要求、最低影响、缺失事实处理和排除条件。
4. 在规则引擎中先产生 Fact，再产生 Finding。
5. 添加危险正例、安全反例、确定性缓解、覆盖缺口和未知节点夹具。
6. 需要运行时确认时只生成惰性动态测试计划。
