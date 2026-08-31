<p align="center">
  <img src="../assets/contextsec-hero.svg" width="100%" alt="ContextSec：判斷哪些安全控制適用，並用證據證明驗證結果。Research preview v0.4.1。" />
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md"><strong>繁體中文</strong></a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

# 依產品情境決定安全控制，並用證據證明結果

**你的 coding agent 知道安全規則；`ContextSec` 告訴它這個產品現在真正需要哪些規則，並讓缺少的證據持續可見。**

`ContextSec` 只讀取有界限的 repository 證據，辨識付款、PII、多租戶、AI、檔案上傳、CI/CD、雲端權限與客服管理等產品情境，再產生適用的控制與 evidence-backed release gate。

它不是通用 OWASP checklist、一般漏洞掃描器、滲透測試或合規認證工具。它不會上傳原始碼、不會執行目標程式碼，也不會把「沒有 finding」誤寫成「已驗證」。

## 60 秒開始使用

需求：Git 與 Python 3.11–3.14。runtime 沒有第三方相依套件。內附的示例刻意保留安全缺口，因此預期 gate 結果是 `BLOCK`。

### Windows — PowerShell

```powershell
git clone https://github.com/niansia/ContextSec.git
Set-Location ContextSec
python --version  # 必須顯示 Python 3.11–3.14
python .agents/skills/contextsec/scripts/contextsec.py doctor
python .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

### macOS — Terminal

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 --version  # 必須顯示 Python 3.11–3.14
python3 .agents/skills/contextsec/scripts/contextsec.py doctor
python3 .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python3 .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python3 .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

### Linux — shell

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 --version  # 必須顯示 Python 3.11–3.14
python3 .agents/skills/contextsec/scripts/contextsec.py doctor
python3 .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python3 .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python3 .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

預期摘要：

```text
required      foundation · baseline-web · auth-session · payments · privacy-pii
              multi-tenant · api-inbound · external-api · file-upload · ai-rag-agent
intersections AI+PII · AI+tenant · API+tenant required
checks        5 failed · 1 unknown · 0 verified
gate          BLOCK — 尚未驗證的必要控制不會被隱藏
```

最後一個指令會刻意以狀態碼 `1` 結束，因為這個示例的 release gate 應該阻擋發布。同一套引擎分析內附的靜態 Next.js 示例時，只會選擇 `foundation` 與 `baseline-web`；它不會對每個 repository 套用全部規則。

要開始分析自己的程式碼時，保留這個 checkout，將 `examples/composite-saas` 換成目標 repository 的絕對路徑即可；先執行 `profile` 並檢視證據，再執行 `check` 與 `gate`。

## `v0.4.1` 目前完成了什麼

| 面向 | 已交付並持續由 CI 驗證 |
|---|---|
| 決策模型 | 16 個 product-risk packs、116 個 catalog controls、9 個跨情境 composition controls |
| 驗證模型 | 完整的 125 列 verification coverage；其中 21 列已有 deterministic checker 或 repository-policy audit |
| Deterministic checks | 10 個公開 checker families，包含正例、反例、mutation 與 adversarial regression |
| 平台 | Windows、macOS、Ubuntu × Python 3.11–3.14 |
| Repository 證據 | 40 個 frozen profile cases，加上 4 個 commit-pinned public-repository cases |
| 發布完整性 | exact-reviewed-main tag、byte-identical archive、3 個 signed assets、draft 重新下載驗證與 immutable Release |

`research preview` 代表獨立生態系準確度尚未建立，不代表 release 工程或 supply-chain controls 仍停留在原型階段。

## 作為 Agent Skill 使用

canonical skill 位於 [`.agents/skills/contextsec`](../../.agents/skills/contextsec)。建議保留在 repository 內，讓來源與版本最清楚；也可以安裝到使用者層級。

### Windows — 選用的 Codex 使用者層級安裝

```powershell
$destination = Join-Path $env:USERPROFILE ".agents\skills\contextsec"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -Recurse -Force ".agents\skills\contextsec\*" $destination
```

### macOS 與 Linux — 選用的 Codex 使用者層級安裝

```bash
mkdir -p ~/.agents/skills/contextsec
cp -R .agents/skills/contextsec/. ~/.agents/skills/contextsec/
```

Claude Code 使用者可將相同資料夾複製到 `.claude/skills/contextsec`。之後可直接提出自然語言要求：

```text
請使用 $contextsec，從這份 PRD 推導安全需求。
請使用 $contextsec，檢查這個 diff 是否啟用了新的產品風險。
請使用 $contextsec 評估發布證據，並回傳 Control Ledger 與 gate。
```

## 信任邊界

- profiling、checks、benchmark 與 ledger evaluation 都是 local-first、read-only、offline。
- repository 內容、README、issue 與註解都視為不可信資料，不會被當成工具指令執行。
- `required`、`candidate`、`inactive`、`unknown` 是適用性；`verified`、`failed`、`unknown`、`waived` 是獨立的驗證狀態。
- 內建 deterministic checks 刻意保持狹窄；沒有 checker 的控制仍需要測試或其他可靠證據。
- `ContextSec` 不宣稱 PCI DSS、GDPR、HIPAA、SOC 2 或其他合規認證。

## 深入閱讀

英文 [README](../../README.md) 是完整且 canonical 的技術入口。另請參考：

- [Architecture](../architecture.md)
- [Benchmark methodology](../benchmark-methodology.md)
- [Independent external evaluation protocol](../external-evaluation-protocol.md)
- [Roadmap and release gates](../roadmap.md)
- [Security policy](../../SECURITY.md)
- [Contributing](../../CONTRIBUTING.md)

最新正式版本：[ContextSec v0.4.1](https://github.com/niansia/ContextSec/releases/tag/v0.4.1)。
