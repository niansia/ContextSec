<p align="center">
  <img src="../assets/contextsec-hero.svg" width="100%" alt="ContextSec：判断哪些安全控制适用，并用证据证明验证结果。Research preview v0.4.1。" />
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <a href="README.zh-CN.md"><strong>简体中文</strong></a> ·
  <a href="README.ja.md">日本語</a>
</p>

# 根据产品情境决定安全控制，并用证据证明结果

**你的 coding agent 知道安全规则；`ContextSec` 告诉它这个产品现在真正需要哪些规则，并让缺失的证据持续可见。**

`ContextSec` 只读取有边界的 repository 证据，识别支付、PII、多租户、AI、文件上传、CI/CD、云权限和客服管理等产品情境，再生成适用的控制与 evidence-backed release gate。

它不是通用 OWASP checklist、普通漏洞扫描器、渗透测试或合规认证工具。它不会上传源代码、不会执行目标代码，也不会把“没有 finding”误写成“已验证”。

## 60 秒开始使用

要求：Git 与 Python 3.11–3.14。runtime 没有第三方依赖。内置示例故意保留安全缺口，因此预期 gate 结果是 `BLOCK`。

### Windows — PowerShell

```powershell
git clone https://github.com/niansia/ContextSec.git
Set-Location ContextSec
python --version  # 必须显示 Python 3.11–3.14
python .agents/skills/contextsec/scripts/contextsec.py doctor
python .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

### macOS — Terminal

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 --version  # 必须显示 Python 3.11–3.14
python3 .agents/skills/contextsec/scripts/contextsec.py doctor
python3 .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python3 .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python3 .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

### Linux — shell

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 --version  # 必须显示 Python 3.11–3.14
python3 .agents/skills/contextsec/scripts/contextsec.py doctor
python3 .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python3 .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python3 .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

预期摘要：

```text
required      foundation · baseline-web · auth-session · payments · privacy-pii
              multi-tenant · api-inbound · external-api · file-upload · ai-rag-agent
intersections AI+PII · AI+tenant · API+tenant required
checks        5 failed · 1 unknown · 0 verified
gate          BLOCK — 尚未验证的必要控制不会被隐藏
```

最后一条命令会有意以状态码 `1` 结束，因为该示例的 release gate 应当阻止发布。同一套引擎分析内置的静态 Next.js 示例时，只会选择 `foundation` 与 `baseline-web`；它不会对每个 repository 套用全部规则。

要开始分析自己的代码，请保留这个 checkout，把 `examples/composite-saas` 替换成目标 repository 的绝对路径；先运行 `profile` 并检查证据，再运行 `check` 与 `gate`。

## `v0.4.1` 目前完成了什么

| 方面 | 已交付并持续由 CI 验证 |
|---|---|
| 决策模型 | 16 个 product-risk packs、116 个 catalog controls、9 个跨情境 composition controls |
| 验证模型 | 完整的 125 行 verification coverage；其中 21 行已有 deterministic checker 或 repository-policy audit |
| Deterministic checks | 10 个公开 checker families，包括正例、反例、mutation 与 adversarial regression |
| 平台 | Windows、macOS、Ubuntu × Python 3.11–3.14 |
| Repository 证据 | 40 个 frozen profile cases，加上 4 个 commit-pinned public-repository cases |
| 发布完整性 | exact-reviewed-main tag、byte-identical archive、3 个 signed assets、draft 重新下载验证与 immutable Release |

`research preview` 表示独立生态准确度尚未建立，不代表 release 工程或 supply-chain controls 仍停留在原型阶段。

## 作为 Agent Skill 使用

canonical skill 位于 [`.agents/skills/contextsec`](../../.agents/skills/contextsec)。建议保留在 repository 内，让来源和版本最清晰；也可以安装到用户级目录。

### Windows — 可选的 Codex 用户级安装

```powershell
$destination = Join-Path $env:USERPROFILE ".agents\skills\contextsec"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -Recurse -Force ".agents\skills\contextsec\*" $destination
```

### macOS 与 Linux — 可选的 Codex 用户级安装

```bash
mkdir -p ~/.agents/skills/contextsec
cp -R .agents/skills/contextsec/. ~/.agents/skills/contextsec/
```

Claude Code 用户可以把同一目录复制到 `.claude/skills/contextsec`。之后可直接提出自然语言请求：

```text
请使用 $contextsec，从这份 PRD 推导安全需求。
请使用 $contextsec，检查这个 diff 是否启用了新的产品风险。
请使用 $contextsec 评估发布证据，并返回 Control Ledger 与 gate。
```

## 信任边界

- profiling、checks、benchmark 与 ledger evaluation 都是 local-first、read-only、offline。
- repository 内容、README、issue 与注释都视为不可信数据，不会被当作工具指令执行。
- `required`、`candidate`、`inactive`、`unknown` 是适用性；`verified`、`failed`、`unknown`、`waived` 是独立的验证状态。
- 内置 deterministic checks 有意保持窄范围；没有 checker 的控制仍需要测试或其他可靠证据。
- `ContextSec` 不宣称 PCI DSS、GDPR、HIPAA、SOC 2 或其他合规认证。

## 深入阅读

英文 [README](../../README.md) 是完整且 canonical 的技术入口。另请参考：

- [Architecture](../architecture.md)
- [Benchmark methodology](../benchmark-methodology.md)
- [Independent external evaluation protocol](../external-evaluation-protocol.md)
- [Roadmap and release gates](../roadmap.md)
- [Security policy](../../SECURITY.md)
- [Contributing](../../CONTRIBUTING.md)

最新正式版本：[ContextSec v0.4.1](https://github.com/niansia/ContextSec/releases/tag/v0.4.1)。
