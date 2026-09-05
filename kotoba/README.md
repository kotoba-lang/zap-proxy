# kotoba/ — zap-proxy の kotoba.net package

zap-proxy 判定核の **Kotoba 言語面**。`java.net.http` で書かれていた host transport
層を、Kotoba の capability モデル（`:http/post` host authority）に載せ替えたもの。

## 構成

```
src/kotoba/zap_proxy/plugin.cljk  # 判定核 guest: typed :http/post 経由の scan I/F
policy.edn                        # {:allow #{[:cap/call 4]}} — :http/post (wire id 4)
build/plugin.wasm                 # amu --target wasm32-kotoba-v1 artifact
build/plugin.mjs                  # amu --target js-kotoba-v1 (restricted ESM) artifact
```

## 設計

- **判定は guest、効果は host。** guest (`plugin.cljk`) は `typed-cap-call :http/post`
  で境界型付き request を投げ、host の bounded provider
  (`provider/http` + `provider/http-transport`、ADR 0066 — allowlist・redirect
  再検証・private-IP block・body 上限) が実際の通信を行う。
  guest に生 socket は存在しない。
- **capability gate**: `(:capabilities #{:http/post})` + policy `{:allow #{[:cap/call 4]}}`。
  deny-by-default。grant 無しでは instantiate も通らない。
- **型**: request/result は capability kit `http-v1.edn`（wire id 4）の正型を
  inline で署名に書く（guest 内の type alias def は未対応のため inline —
  alias 構文が入ったら差し替え）。
- result は `:variant :kotoba.http/result`。`variant-match` で ok/error を分岐し、
  `record-get` で `:status` 等を取り出す。

## 検証（実測 2026-09-05）

```sh
amu check kotoba/src/kotoba/zap_proxy/plugin.cljk --policy kotoba/policy.edn
# → :ok true
amu compile … --target wasm32-kotoba-v1 --output build/plugin.wasm   # :ok true
amu compile … --target js-kotoba-v1      --output build/plugin.mjs   # :ok true
```

mesh `run` ABI の deployable component も同型（`kotoba component build` で
正準 CID が発行される。WIT run ABI は 1 payload なので scan protocol は EDN text
で運ぶ — typed request 経路は上記 amu artifact 側）。

## 既知ギャップ

- guest 内 type alias（`(def http-request-type …)` を型位置で参照）は未対応 —
  inline 型署名で回避中。alias 構文の admission が来たら差し替える。
- `(:const …)` 型位置参照も未対応（同上）。
- 本 artifact の実 host 配線（provider http-transport を Biscuit/CACAO 付きで
  kotobase.net 向けに bind）は plugin/ の Python host が当面担当。
