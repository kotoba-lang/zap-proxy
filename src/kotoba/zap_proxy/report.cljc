(ns kotoba.zap-proxy.report
  "Report generation. Equivalent of ZAP's report add-on: turns findings into
  an EDN document (canonical) and a JSON rendering. Pure."
  (:require [clojure.string :as str]
            [kotoba.zap-proxy.core :as core]))

(def ^:private json-esc
  (fn [s] (-> s (str/replace "\\" "\\\\") (str/replace "\"" "\\\"")
              (str/replace "\n" "\\n") (str/replace "\r" "\\r") (str/replace "\t" "\\t"))))

(defn- json-str [s] (str "\"" (json-esc (str s)) "\""))

(defn- finding->json [f]
  (str "{"
       "\"rule_id\":" (json-str (:rule-id f)) ","
       "\"severity\":" (json-str (name (get f :severity :low))) ","
       "\"title\":" (json-str (:title f)) ","
       "\"url\":" (json-str (:url f)) ","
       "\"evidence\":" (json-str (:evidence f))
       (when-let [p (:param f)] (str ",\"param\":" (json-str p)))
       (when-let [s (:solution f)] (str ",\"solution\":" (json-str s)))
       "}"))

(defn report-edn
  "Canonical report document (EDN map). One map per scan."
  [{:keys [target findings started-at]}]
  (let [by-sev (group-by :severity findings)]
    {:report/version 1
     :report/target target
     :report/started-at started-at
     :report/counts (into {} (for [[s fs] by-sev] [s (count fs)]))
     :report/total (count findings)
     :report/findings (vec findings)}))

(defn report-json
  "JSON string rendering of the same report."
  [{:keys [target findings] :as doc}]
  (let [r (report-edn doc)]
    (str "{"
         "\"target\":" (json-str target) ","
         "\"total\":" (:report/total r) ","
         "\"counts\":{"
         (str/join "," (for [[s n] (:report/counts r)]
                         (str (json-str (name s)) ":" n)))
         "},"
         "\"findings\":[" (str/join "," (map finding->json findings)) "]"
         "}")))
