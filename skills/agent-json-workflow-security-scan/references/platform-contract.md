# Platform Contract

## 输入外形

支持两种已观察到的入口：

- 直接图对象：`{id, nodes, edges, historyContextConfig}`；
- API 包装对象：`{body: {body: {id, nodes, edges, ...}, ...}, ...}`。

解析器只把 `nodes` 与 `edges` 当作画布结构。`reactflow__edge-*`、坐标、宽高、动画和选中状态不参与安全结论。

当前字段契约标识为 `internal-json-workflow/observed-2026-08`。每个已知节点类型有显式字段集合；未来导出若出现未映射字段，解析器记录 `unmapped_node_field` 覆盖缺口，而不是静默丢弃或按字段名猜测漏洞。

## 显式节点映射

| 原始类型 | IR 类型 | 主要语义 |
|---|---|---|
| `HEAD` | `INPUT` | 系统/用户入口，`paramList` 声明输入契约 |
| `TEMPLATE` | `OUTPUT` | 最终输出与引用 |
| `INTERMEDIATE_OUTPUT` | `OUTPUT` | 中间输出边界 |
| `MODEL` | `LLM` | Prompt、模型参数和输出契约 |
| `AGENT` | `AGENT` | 自主规划、工具注册、知识与模型上下文 |
| `AI_PLUGIN`、`API_PLUGIN`、`MCP`、`WORKFLOW` | `TOOL` | 外部能力、子工作流和参数边界 |
| `NEW_KNOWLEDGE` | `KNOWLEDGE` | 检索配置、数据集和来源元数据 |
| `CODE` | `CODE` | 固定内嵌代码；默认视为数据转换 |
| `JUDGE` | `CONDITION` | `conditionList` 与 `handleId/sourceIndex` 分支 |
| `LOOP` | `LOOP` | 容器节点，递归包含内部 nodes/edges |
| `LOOP_START`、`LOOP_OUTPUT` | `STRUCTURAL` | 循环内部结构节点 |

## 绑定与符号

- 节点 `outputName` 建立生产者符号；`params/input/output/body/query/header/loopInput` 中 `variableType=REFERENCE` 建立消费者引用。
- `systemInput.<field>` 直接绑定入口字段。
- LOOP 内部输入以平台导出的稳定符号 `loopStart` 绑定同容器的 `LOOP_START` 节点；这是本平台方言，不是 React Flow 语义。
- Prompt 中 `${name}` 先绑定同节点参数，再解析参数所引用的全局符号。
- 同名生产者按控制流可达性消歧；无法唯一解析时保留所有候选并记录 `ambiguous_symbol`。
- 空引用、必填但无值、未知类型和容器内部不完整路径都保留 JSON Pointer 证据。
- `AGENT.tools[].toolList[].toolParamConfig` 内的引用会递归进入数据流，不局限于节点顶层参数。

## Agent 工具注册

`AGENT.data.tools` 及其嵌套 `toolList` 统一规范化为工具规格，保留：类型、注册键、父工具、版本、来源、认证声明、HTTP 方法、参数位置、必填、是否禁用和 Agent 可见性。`knlToolList` 作为 Agent 附加知识边界解析。

样例不证明 `disabled`、`canAgentSee`、`auth` 的完整运行时语义。规则只能在字段语义确定时给出确定结论，否则输出覆盖缺口。
