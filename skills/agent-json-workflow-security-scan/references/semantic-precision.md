# JSON DSL 扫描语义精度改进（0.2.0）

本轮保留 54 条规则 ID 与既有 JSON DSL 输入契约，扩充规则的语义检测能力；不以规则数量作为准确率指标。输入仍为 JSON，IR、Fact、Finding 和门禁仍在内存中传递，最终产物仍是单文件 HTML。

## 参考与取舍

参考仓库为 [agent-workflow-security-scan，26fbb359](https://github.com/vic-uoa/agent-workflow-security-scan/tree/26fbb35959b3f859d9e8d31522ac20928839dd3d)，读取了 `semantics.py` 与 `tests/test_semantic_precision.py`。采用调用参数、字段语义与保守覆盖的设计方向；内部 JSON 的引用、循环和分支契约继续使用本库解析器，不引入 Dify 选择器格式。

成熟扫描库提供的参考原则：

- [Semgrep 污点分析](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview)：区分源、传播、危险消费点和净化器；缩小字段与参数匹配范围，不能因为节点名称或 Schema 声明就抹除整条污染路径。
- [Bandit B602](https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html)：进程能力、shell 模式和命令内容需要分别分析。固定程序接收数据参数，不直接证明 shell 注入。
- [Gitleaks 配置](https://github.com/gitleaks/gitleaks#configuration)：凭据特征与允许列表应有明确匹配范围。本库采用候选值级占位符豁免与供应商格式检测；未引入完整 Gitleaks 规则集或其全部熵检测能力。

上述项目是设计和回归场景参考，不是本扫描器已集成的执行后端。本次没有新增外部扫描二进制、联网凭据验证或运行被扫描代码。

## 已修复的误报与漏检

| 范围 | 原问题 | 现在的判定 |
|---|---|---|
| Python CODE | `urllib.parse` 等前缀被视为网络访问；网络、文件、进程一律高危 | AST 定位实际调用及敏感参数；固定参数记录 posture，动态解释器/SQL/反序列化参数为 HIGH/PROBABLE |
| 调用解析 | `import … as …`、`from … import …` 和局部可调用别名可能绕过匹配 | 解析作用域内导入、赋值别名；记录调用名、代码行与参数名 |
| SQL 与 shell | 绑定值、固定 argv 可能混同解释器源代码 | 检查 SQL 第一参数和 shell/解释器命令参数；`shell=False` 的固定非解释器程序数据 argv 不报注入 |
| 网络目标 | URL 任意动态部分都可能被当成 SSRF | CODE 对 URL 的固定 scheme/authority 与动态 path/query 分开；动态主机保留 PROBABLE，插件不猜测注册表实现 |
| 跨节点传播 | CODE 中转后不可信来源丢失 | 沿数据引用图回溯到不可信源；画布控制边不作为数据传播证据 |
| 对象字段 | 读取某个叶子却继承兄弟 URL/敏感字段 | 叶子绑定只检查所选字段，整对象仍递归检查子字段；敏感披露链从实际绑定的敏感字段开始 |
| 授权门 | `NE true`、无关布尔值、OR 旁路、用户提供 approved 可能消除风险 | 要求正向等值授权谓词、明确组合语义、无不可信数据流入及一致分支映射；未知或未解析引用不能证明授权 |
| 图搜索 | 路径超过 64 层静默丢失，集合顺序影响证据 | 使用父指针 BFS 遍历有界节点图；稳定邻居顺序、环去重，不按路径长度截断 |
| 凭据 | 同一文本含 example 就全局豁免；JSON 键值分离漏检；`/nodes/1` 匹配 `/nodes/10` | 按候选值精确豁免；扫描 JSON 键值、参数描述项与所有节点/图元数据；按路径分隔符及最深所属节点归属 |
| 输入一致性 | JSON 重复键依赖解析器覆盖顺序，接受 NaN/Infinity | 拒绝重复键与非有限常量，避免扫描器和运行时解析分歧 |
| 完整性 | 代码语法/调用无法解析却计为运行时缺口 | `TOOL-011` 及聚合中的关联规则令扫描完整性为 INCOMPLETE |
| 豁免 | 有 expires_at 字段即可豁免，缺少 DSL 哈希也允许 | 必须匹配当前 DSL 哈希，时间必须带时区且未到期；不合格记录进入 rejected |

## 内存证据格式

CODE 的 Fact.data 新增可选 `semantic_evidence`，不改变已有必填接口：

```json
{
  "analysis": "python_ast",
  "call": "subprocess.run",
  "line": 3,
  "kind": "CODE_PROCESS",
  "dynamic_argument": true,
  "argument_names": ["command"]
}
```

Fact.evidence 保存代码字段 JSON Pointer；Finding 消息提供调用名与行号。不将凭据原文加入这些证据。凭据结论表示字面量特征存在，不表示已联网确认密钥有效。

## 准确率与覆盖边界

新增的成对正反例用于验证已知缺陷，并不代表真实业务样本上的误报率、召回率或准确率百分比。验证命令：

```powershell
python -m unittest discover -s skills/agent-json-workflow-security-scan/tests -p "test_*.py"
python skills/agent-json-workflow-security-scan/scripts/validate_suite.py --output build/semantic-validation
```

本轮验证：61 个单元测试通过（原有 35 个，新增 26 个）；5 份工作流验证夹具均满足预期。原安全夹具 PASS/0 风险，原危险夹具 FAIL，契约夹具 REVIEW；新增语义安全夹具 PASS/0 风险，动态命令与网络目标夹具 REVIEW。代码动态参数属于 PROBABLE，控制路径不能再次把它升级为已确认宿主或授权漏洞；仍要求人工复核和运行时证据。

Python 分析是保守的调用点摘要，不是完整解释器、跨函数污点证明或路径可满足性证明。对象反射、动态导入、未知库调用、解析失败及预算耗尽均保留覆盖缺口。普通 CODE 中转不自动清除污染；目前没有证明任意转换器能够安全净化某个字段的能力。局部赋值采用合并语义，对复杂重赋值、实例路径和 helper 参数可能保留额外观察或候选风险。

固定 authority 不证明 DNS、重定向、代理或出口策略安全；固定 argv 不证明被调用程序的所有选项无害；参数化 SQL 的实现依赖驱动。本轮仅减少“直接注入”误判，不豁免这些外部事实。授权条件没有不可信引用，也仅能说明导出的控制结构成立，IAM 与对象归属仍需运行时证据。

本轮仍未覆盖完整 JavaScript 语义、任意库的隐式网络调用、编码后凭据及第三方工具实现。未知能力不应被解释为安全通过。
