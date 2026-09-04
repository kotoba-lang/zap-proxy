(ns kotoba.zap-proxy.core
  "Shared data model for the zap-proxy DAST stack.

  Pure. No I/O. An HTTP round-trip is always a pair of plain maps:

    {:method \"GET\" :url \"https://h/p\" :headers {..} :body \"..\"}
    {:status 200 :headers {..} :body \"..\"}

  A scan session is an append-only vector of observations; every rule sees the
  same immutable shapes and reports plain findings maps."
  {:author "kotoba-lang"})

(def ^:const finding-severity {:info 0 :low 1 :medium 2 :high 3})

(defn finding
  "A single diagnostic result. `rule-id` is a stable string (e.g. \"10038\"),
  matching the ZAP-style numeric convention but defined by our own registry in
  resources/zap_proxy/rules/rules.edn."
  [{:keys [rule-id severity title evidence url param solution references]
    :or {severity :low}}]
  (cond-> {:rule-id rule-id
           :severity severity
           :title title
           :evidence evidence
           :url url}
    param      (assoc :param param)
    solution   (assoc :solution solution)
    references (assoc :references references)))

(defn target-origin
  "scheme://host:port of a URL — the same-origin boundary for the spider.
  Pure string work so it is testable without any network."
  [url]
  (let [clean (if (re-find #"^[a-zA-Z][a-zA-Z0-9+.-]*://" url) url (str "http://" url))
        [_ scheme rest] (re-matches #"([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)" clean)
        [auth _path] (split-with #(not= % \/) (seq rest))
        auth (apply str auth)
        default-port (case scheme "https" "443" "80")
        [host port] (if-let [[_ h p] (re-matches #"([^:]+):(\d+)" auth)]
                      [h p] [auth default-port])]
    {:scheme scheme :host host :port port}))

(defn same-origin?
  "Spider scope: URL is in scope when its origin equals the target's origin."
  [base-url other-url]
  (= (target-origin base-url) (target-origin other-url)))

(defn normalize-url
  "Strip fragments; keep query. Spider candidates are deduped on this."
  [url]
  (let [clean (if (re-find #"^[a-zA-Z][a-zA-Z0-9+.-]*://" url) url (str "http://" url))]
    (subs clean 0 (or (some-> (clojure.string/index-of clean "#") (max 0)) (count clean)))))

(def ^:private default-robots-user-agent "zap-proxy/0.1 (clean-room DAST; defense-side)")
