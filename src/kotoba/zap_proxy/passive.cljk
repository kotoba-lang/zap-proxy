(ns kotoba.zap-proxy.passive
  "Passive scanner — non-intrusive checks on responses already observed.
  Equivalent of ZAP's passive scan rules. Maps to IPA「ウェブ健康診断仕様」
  categories that only need response inspection (no payload injection):
  missing security headers, cookie flags, sensitive-info in responses.

  Pure functions over (request, response) pairs; findings are produced with
  rule IDs from the rules registry."
  (:require [kotoba.lang.text :as str]
            [kotoba.zap-proxy.core :as core]))

(defn- header-lower [resp name]
  (->> (get resp :headers {})
       (some (fn [[k v]] (when (= (str/lower (str k)) (str/lower (str name))) v)))))

(defn check-security-headers
  "IPA 仕様のセキュリティ関連 HTTP ヘッダ出力。RULE 10038 (ZAP-style id)."
  [{:keys [url]} resp]
  (let [required {"strict-transport-security" "HSTS not set (IPA セキュリティ関連HTTPヘッダ)"
                  "x-content-type-options"    "X-Content-Type-Options not set (MIMEスニッフィング対策)"
                  "content-security-policy"   "Content-Security-Policy not set (XSS 軽減)"
                  "x-frame-options"           "X-Frame-Options not set (クリックジャッキング対策)"}]
    (for [[h why] required
          :when (nil? (header-lower resp h))]
      (core/finding {:rule-id "10038"
                     :severity :low
                     :title why
                     :evidence (str "missing header: " h)
                     :url url
                     :solution (str "Set the " h " response header.")}))))

(defn check-cookie-flags
  "IPA セッション管理の Cookie 属性 (Secure / HttpOnly / SameSite). RULE 10010.
  A header value may be a vector (java.net.http multi-value Set-Cookie) —
  each cookie is checked independently."
  [{:keys [url]} resp]
  (let [raw (->> (get resp :headers {})
                 (filter (fn [[k _]] (= (str/lower (name k)) "set-cookie")))
                 (map (fn [[_ v]] v)))
        cookies (mapcat (fn [v] (if (sequential? v) (map str v) [(str v)])) raw)]
    (for [sc cookies
          flag [[#"(?i)secure" "Secure"] [#"(?i)httponly" "HttpOnly"] [#"(?i)samesite" "SameSite"]]
          :when (not (re-find (first flag) sc))]
      (core/finding {:rule-id "10010"
                     :severity :medium
                     :title (str "Cookie missing " (second flag) " attribute (IPA セッション管理)")
                     :evidence sc
                     :url url
                     :solution (str "Set the " (second flag) " attribute on the cookie.")}))))

(def ^:private sensitive-patterns
  [[#"(?i)password\s*[:=]\s*[^&\"'\s]+" "possible credential echoed in response"]
   [#"(?i)\bAKIA[0-9A-Z]{16}\b" "AWS access key id pattern in response"]
   [#"(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----" "private key material in response"]
   [#"jdbc:[a-z0-9]+://[^\"'\s]+" "JDBC connection string in response"]])

(defn check-sensitive-info
  "IPA「Webアプリケーションの情報漏えい」. RULE 10027."
  [{:keys [url]} resp]
  (let [body (get resp :body "")]
    (for [[re why] sensitive-patterns
          :let [m (re-find re body)]
          :when m]
      (core/finding {:rule-id "10027"
                     :severity :high
                     :title (str "Sensitive information disclosure: " why)
                     :evidence (subs (str m) 0 (min 40 (count (str m))))
                     :url url
                     :solution "Remove the secret from the response; rotate any exposed credential."}))))

(def checks
  "Ordered passive rule list — one fn per rule, all (req resp) -> [findings]."
  [check-security-headers check-cookie-flags check-sensitive-info])

(defn passive-scan
  "Run every passive check over one (request, response) pair."
  [req resp]
  (vec (mapcat (fn [f] (f req resp)) checks)))
