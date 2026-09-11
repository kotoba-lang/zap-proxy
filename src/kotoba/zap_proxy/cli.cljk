(ns kotoba.zap-proxy.cli
  "Application entry — the zap-cli equivalent. Orchestrates
  spider → passive scan (per crawled page) → active scan (opt-in) → report.

  The only effects in this namespace are the injected fetch-fn / send-fn the
  caller passes in; there is no direct socket code here either. A real
  deployment injects a transport built on `kotoba-lang/http` wire layer or a
  host capability; tests inject the mock."
  (:require [kotoba.zap-proxy.core :as core]
            [kotoba.zap-proxy.spider :as spider]
            [kotoba.zap-proxy.passive :as passive]
            [kotoba.zap-proxy.active :as active]
            [kotoba.zap-proxy.report :as report]))

(defn scan
  "Full scan pipeline.

  opts:
    :target     seed URL (required)
    :fetch-fn   request -> response, used by the spider (required)
    :send-fn    request -> response, used by active probes (defaults to fetch-fn)
    :active?    run intrusive probes (default false — passive-only is the safe default)
    :max-pages  spider cap (default 50)
  Returns the report document."
  [{:keys [target fetch-fn send-fn active? max-pages started-at]
    :or {max-pages 50 active? false}
    :as opts}]
  {:pre [(some? target) (ifn? fetch-fn)]}
  (let [send-fn' (or send-fn fetch-fn)
        {:keys [pages]} (spider/spider {:seed-url target :fetch-fn fetch-fn :max-pages max-pages})
        passive-findings (vec (mapcat (fn [resp] (passive/passive-scan {:url (:url resp)} resp)) pages))
        active-findings (if active?
                          (vec (mapcat (fn [resp] (active/active-scan {:url (:url resp)
                                                                      :send-fn send-fn'})))
                                       pages)
                          [])
        findings (vec (concat passive-findings active-findings))]
    (report/report-edn {:target target :findings findings :started-at started-at})))
