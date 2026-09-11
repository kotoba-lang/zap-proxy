# hermes-zap-proxy plugin

Hermes agent から `kotoba-lang/zap-proxy` の DAST 判定核を呼ぶ plugin。
プラグイン設計の正本は Hermes 本家 docs（`plugin.yaml` + `register(ctx)` + schemas/tools）。

## 構成（4 ファイル）

```
plugin/
├── plugin.yaml   # manifest v2: name / provides_tools / config_schema
├── __init__.py   # register(ctx) — 3 tools を toolset "zap-proxy" に登録
├── schemas.py    # LLM が読むツール仕様（引数・説明）
└── tools.py      # ハンドラ。own-host gate はここでコードとして強制
src/kotoba/zap_proxy/plugin_entry.cljk  # 判定核と agent の橋。EDN in → EDN report out
```

## ツール

| tool | 何 | gate |
|---|---|---|
| `zap_scan` | passive scan（spider → ヘッダ/Cookie/情報漏えい検査） | target が `zap_proxy_targets` に登録済みであること |
| `zap_scan_active` | active scan（SQLi/XSS/CMDi/Trav/CRLF probe） | 上記 + その target に `allow_active: true` |
| `zap_scan_rules` | ルール登録簿 8 件の表示 | 無し（読み取りのみ） |

## 安全境界（コードで強制、モデル判断に委ねない）

1. **own-host gate**: target の origin（scheme://host:port）が
   `plugins.entries.hermes-zap-proxy.settings.zap_proxy_targets` に一致しなければ
   subprocess を起動する前に拒否。第三者 host は原理的に scan できない。
2. **active の二重 gate**: `allow_active: true` が無い target には主走査も拒否。
3. **効果の分離**: ネットワーク効果は `plugin_entry.clj`（java.net.http transport）だけが
   持ち、判定核は pure のまま。plugin は `kbb -M -m kotoba.zap-proxy.plugin-entry`
   を固定 argv で呼ぶ（shell 文字列を組まない）。

## install（この workspace）

```
plugin/ → ~/.hermes/profiles/itonami/plugins/hermes-zap-proxy/
config.yaml: plugins.enabled に hermes-zap-proxy を追加
```

⚠ `hermes plugins list` の user plugins は `~/.hermes/plugins/` ではなく
**profile の plugins/（`~/.hermes/profiles/<p>/plugins/`）** を見る（実測 2026-09-05）。

## 検証（実測 2026-09-05）

- `hermes plugins doctor`: discovery / manifest / import / registration 全部 OK、3 tools
- localhost:8765（Python http.server）に対する `zap_scan` via agent: **12 findings
  （low 12 = rule 10038 × 3 URL × 4 ヘッダ）** を実ネットワークで取得
- `zap_scan_active` は `allow_active` 無しの target で refused（gate 実働）
- 未登録 target（example.com）は refused
- 判定核テスト: 10 tests / 35 assertions green（plugin 追加後も回帰無し）
