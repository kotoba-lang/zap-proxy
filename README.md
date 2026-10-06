# zap-proxy

**kotoba-lang/zap-proxy は Kotoba/Clojure で書いた Web 脆弱性診断（DAST）
スタックである。** 自分の管理下の Web アプリに対して spider → passive scan →
active scan（opt-in）→ report を実行する。

- OWASP ZAP のソースコード・スキャンルール・ポリシー・payload/wordlist・JAR は
  含まない。実行時に OWASP ZAP（daemon / API）を呼び出すこともない。
  判定ロジック・payload・ルール登録簿はすべてこの repo で書いたものである。
- repo 名の "zap" はプロジェクト名であり、OWASP ZAP プロジェクトとの提携・承認を
  意味しない。
- ルール ID（`10038`, `40018` など）は 5 桁の数値形式を採っているが、定義
  （タイトル・判定条件・payload・対処）はこの repo 独自のもので、OWASP ZAP の
  同じ番号のルールとは内容が一致しない場合がある（`resources/zap_proxy/rules/rules.edn`
  が正本）。

## 構成（この 1 repo に lib と app を同居させる）

MITM（intercepting）プロキシはまだ実装していない。HTTP の送受信は呼び出し側が
`:fetch-fn` / `:send-fn` として注入する。

| 層 | 何 | 出力 |
|---|---|---|
| **lib** `kotoba.zap-proxy.core` | 共有データモデル（request/response map、finding、same-origin 判定、URL 正規化） | pure map |
| **lib** `kotoba.zap-proxy.spider` | クロール（リンク/フォーム抽出、same-origin 判定） | 取得ページ列・訪問済み URL |
| **lib** `kotoba.zap-proxy.passive` | レスポンス非侵襲検査（ヘッダ、Cookie、情報漏えい） | findings |
| **lib** `kotoba.zap-proxy.active` | 侵襲検査（SQLi/XSS/path traversal 等の payload 適用と反応判定） | findings |
| **data** `resources/zap_proxy/rules/rules.edn` | ルール登録簿（EDN。ID/重要度/IPA・OWASP WSTG 参照） | 8 件 |
| **lib** `kotoba.zap-proxy.report` | 診断レポート生成（EDN/JSON） | report 文書 |
| **app** `kotoba.zap-proxy.cli` | 1 コマンドで全段階を実行する入口 | report 文書 |

設計規約（AGENTS.md / ADR-2609060001）:

- 判定核（何を脆弱とみなすか・payload は何か・same-origin はどう決まるか）は
  全て pure `.cljc`。効果（実送信、実ソケット）は host 側 `:send-fn` / `:fetch-fn`
  に注入する — `kotoba-lang/http` の `IHttp` と同じ seam。
- 診断項目は `orgs/cloud-itonami/app-wvme/SPEC.tsv`（IPA「ウェブ健康診断仕様」
  125 項目 + OWASP STG）と `manifest/` 側の security governance
  （`kotoba-lang/security`）を参照する。**攻撃実行・侵入・兵器運用は scope 外** —
  これは自分の管理下の Web アプリを診断する防御側ツールである。

## 使い方

```clojure
(require '[kotoba.zap-proxy.cli :as cli])

(cli/scan {:target "http://localhost:8080"
           :fetch-fn my-http-fetch   ; IHttp 相当。テストは mock-http
           :send-fn my-http-send
           :passive? true :active? false})
```

## Test

```sh
kbb -M:test
python3 -m unittest plugin.test_tools
```

## Hermes plugin

The repository root is also an installable Hermes plugin. Installation keeps
the Python host adapter, `.cljk` decision core, rule registry, and pinned
dependencies in one reviewed checkout:

```sh
hermes plugins install kotoba-lang/zap-proxy --ref <40-character-commit> --enable
```

Passive and active scans are refused until the target origin is listed under
`plugins.entries.hermes-zap-proxy.settings.zap_proxy_targets`. Active scanning
also requires `allow_active: true`. The host must provide the `clojure` CLI.

## License

MIT License. Copyright (c) 2026 Kotoba Labs, Inc. See [LICENSE](LICENSE).
