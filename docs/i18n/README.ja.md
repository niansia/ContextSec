<p align="center">
  <img src="../assets/contextsec-hero.svg" width="100%" alt="ContextSec：適用すべきセキュリティ制御を判断し、検証結果を証拠で示します。Research preview v0.4.1。" />
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md"><strong>日本語</strong></a>
</p>

# 製品の実態に合うセキュリティ制御を選び、証拠で検証する

**コーディングエージェントはセキュリティ規則を知っています。`ContextSec` は、この製品に今必要な規則を判断し、不足している証拠を見える状態に保ちます。**

`ContextSec` は境界を定めて repository の証拠を読み取り、決済、PII、マルチテナント、AI、ファイルアップロード、CI/CD、クラウド権限、サポート管理などの製品コンテキストを識別します。その上で、適用すべき制御と evidence-backed release gate を生成します。

汎用的な OWASP checklist、一般的な脆弱性スキャナー、ペネトレーションテスト、コンプライアンス認証ではありません。ソースコードをアップロードせず、対象コードを実行せず、「finding がない」ことを「検証済み」に置き換えません。

## 60 秒で試す

必要なもの：Git と Python 3.11–3.14。runtime にサードパーティ依存はありません。同梱の例には意図的にセキュリティ上の不足が残されているため、想定される gate 結果は `BLOCK` です。

### Windows — PowerShell

```powershell
git clone https://github.com/niansia/ContextSec.git
Set-Location ContextSec
python --version  # Python 3.11–3.14 と表示される必要があります
python .agents/skills/contextsec/scripts/contextsec.py doctor
python .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

### macOS — Terminal

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 --version  # Python 3.11–3.14 と表示される必要があります
python3 .agents/skills/contextsec/scripts/contextsec.py doctor
python3 .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python3 .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python3 .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

### Linux — shell

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 --version  # Python 3.11–3.14 と表示される必要があります
python3 .agents/skills/contextsec/scripts/contextsec.py doctor
python3 .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python3 .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python3 .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

想定される要約：

```text
required      foundation · baseline-web · auth-session · payments · privacy-pii
              multi-tenant · api-inbound · external-api · file-upload · ai-rag-agent
intersections AI+PII · AI+tenant · API+tenant required
checks        5 failed · 1 unknown · 0 verified
gate          BLOCK — 未検証の必須制御を隠さない
```

最後のコマンドは意図的に終了コード `1` を返します。この例の release gate は公開をブロックするのが正しいためです。同じエンジンで同梱の静的 Next.js 例を分析すると、選択されるのは `foundation` と `baseline-web` だけです。すべての repository に全ルールを適用する仕組みではありません。

自分のコードを分析するには、この checkout を残したまま `examples/composite-saas` を対象 repository の絶対パスに置き換えます。まず `profile` の証拠を確認し、その後 `check` と `gate` を実行してください。

## `v0.4.1` で実装済みの内容

| 分野 | 実装済みで CI が継続検証している内容 |
|---|---|
| 決定モデル | 16 product-risk packs、116 catalog controls、9 cross-context composition controls |
| 検証モデル | 125 行すべての verification coverage。うち 21 行に deterministic checker または repository-policy audit が存在 |
| Deterministic checks | 公開された 10 checker families。positive、negative、mutation、adversarial regression を含む |
| プラットフォーム | Windows、macOS、Ubuntu × Python 3.11–3.14 |
| Repository 証拠 | 40 frozen profile cases と 4 commit-pinned public-repository cases |
| リリース完全性 | exact-reviewed-main tag、byte-identical archive、3 signed assets、draft の再ダウンロード検証、immutable Release |

`research preview` は独立したエコシステム精度がまだ確立されていないことを示します。release engineering や supply-chain controls が試作段階という意味ではありません。

## Agent Skill として使う

canonical skill は [`.agents/skills/contextsec`](../../.agents/skills/contextsec) にあります。出所とバージョンを明確にするため repository-local での利用を推奨しますが、ユーザー領域にもインストールできます。

### Windows — 任意の Codex ユーザーインストール

```powershell
$destination = Join-Path $env:USERPROFILE ".agents\skills\contextsec"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -Recurse -Force ".agents\skills\contextsec\*" $destination
```

### macOS / Linux — 任意の Codex ユーザーインストール

```bash
mkdir -p ~/.agents/skills/contextsec
cp -R .agents/skills/contextsec/. ~/.agents/skills/contextsec/
```

Claude Code では、同じフォルダーを `.claude/skills/contextsec` にコピーできます。その後は自然言語で依頼できます。

```text
$contextsec を使って、この PRD からセキュリティ要件を導出してください。
$contextsec を使って、この diff で新しい製品リスクが有効になったか確認してください。
$contextsec を使ってリリース証拠を評価し、Control Ledger と gate を返してください。
```

## 信頼境界

- profiling、checks、benchmark、ledger evaluation は local-first、read-only、offline です。
- repository の内容、README、issue、コメントは信頼できないデータとして扱い、ツールへの命令として実行しません。
- `required`、`candidate`、`inactive`、`unknown` は適用性です。`verified`、`failed`、`unknown`、`waived` は独立した検証状態です。
- 内蔵 deterministic checks の対象は意図的に限定されています。checker がない制御にはテストなど別の信頼できる証拠が必要です。
- `ContextSec` は PCI DSS、GDPR、HIPAA、SOC 2 などの認証を主張しません。

## 詳細ドキュメント

英語版 [README](../../README.md) が完全な canonical 技術入口です。以下も参照してください。

- [Architecture](../architecture.md)
- [Benchmark methodology](../benchmark-methodology.md)
- [Independent external evaluation protocol](../external-evaluation-protocol.md)
- [Roadmap and release gates](../roadmap.md)
- [Security policy](../../SECURITY.md)
- [Contributing](../../CONTRIBUTING.md)

最新の正式リリース：[ContextSec v0.4.1](https://github.com/niansia/ContextSec/releases/tag/v0.4.1)。
