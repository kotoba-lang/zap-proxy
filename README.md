# zap-proxy

**kotoba-lang/zap-proxy は OWASP ZAP (zaproxy.org) 相当の Web 脆弱性診断
スタックの clean-room 実装である。** OWASP ZAP 本体の XML・JAR・スクリプトは
1 バイトも含まず、公開仕様（DAST の概念モデル: spider → passive scan →
active scan → report）だけを参照して、Kotoba/Clojure スタックで書いた。

## 構成（この 1 repo に lib と app を同居させる）

| 層 | 何 | 何に相当 |
|---|---|---|
| **lib** `kotoba.zap-proxy.proxy` | ローカル MITM HTTP プロキシのデータモデルと判定核 | ZAP の intercepting proxy |
| **lib** `kotoba.zap-proxy.spider` | クロール（リンク/フォーム抽出、same-origin 判定） | ZAP Spider |
| **lib** `kotoba.zap-proxy.passive` | レスポンス非侵襲検査（ヘッダ、Cookie、情報漏えい） | ZAP Passive Scanner |
| **lib** `kotoba.zap-proxy.active` | 侵襲検査（SQLi/XSS/path traversal 等の payload 適用と反応判定） | ZAP Active Scanner |
| **lib** `kotoba.zap-proxy.rules` | ルール登録簿（EDN。ID/重要度/参照） | ZAP の scan rules |
| **lib** `kotoba.zap-proxy.report` | 診断レポート生成（EDN/JSON） | ZAP Report |
| **app** `kotoba.zap-proxy.cli` | 1 コマンドで全段階を実行する入口 | `zap-cli -quickurl` |

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
```
