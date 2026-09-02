# Agent JSON Workflow Security Scan

面向内部 JSON 工作流编排格式的确定性静态安全扫描器。项目以 Codex Skill 形式交付，解析画布节点、嵌套循环、变量绑定、Agent 工具注册、MCP、插件、知识库和内嵌代码，生成可审计的风险证据、输入测试簇、攻击面与质量门禁。

当前实现位于 `skills/agent-json-workflow-security-scan/`。扫描器不会运行工作流、工具、MCP、Prompt 或内嵌代码。

当前内部方言契约覆盖 `HEAD`、`MODEL`、`AGENT`、插件、MCP、知识库、子工作流、`CODE`、`JUDGE`、`LOOP` 和输出节点，并为每个节点输出多维审核记录。确定性引擎独占 Finding 和质量门禁；可选模型顾问只能补充经过引用校验的惰性测试、复核问题和非权威措辞。

```powershell
python skills/agent-json-workflow-security-scan/scripts/scan_workflow.py scan `
  --dsl <workflow.json> --output <output-directory> --mode structure-only
```

扫描器只写入一份自包含 HTML 报告。`--output` 表示报告根目录，实际目录和报告文件名会跟随上传的工作流文件名：

```text
<output-directory>/
└─ <workflow-name>/
   └─ <workflow-name>-安全扫描报告.html
```

Workflow IR、确定性事实、规则候选、输入簇、Finding、攻击面和质量门禁全部在扫描进程内存中传递，不会作为 JSON 或 Markdown 中间文件落盘。报告包含由 DSL 转换的完整工作流 SVG，以及与每项风险就地绑定的聚焦逻辑链 SVG；所有样式、脚本和图形均内嵌，可离线查看。
