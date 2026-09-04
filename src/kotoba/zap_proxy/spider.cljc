(ns kotoba.zap-proxy.spider
  "Crawler. Equivalent of ZAP's spider: fetch the seed URL, extract links and
  form actions, enqueue same-origin candidates, dedupe on normalized URL.

  The HTTP effect is injected: `fetch-fn` receives a request map and returns a
  response map (see kotoba.zap-proxy.core). Nothing here opens a socket."
  (:require [clojure.string :as str]
            [kotoba.zap-proxy.core :as core]))

(defn extract-links
  "All href/src/action URLs from an HTML body. Pure regex extraction — this is
  a defensive scanner, not a browser engine; JS-discovered endpoints are out of
  scope for this tier (documented gap in ADR-2609060001)."
  [body]
  (let [hrefs (re-seq #"(?i)(?:href|src|action)\s*=\s*[\"']([^\"']+)[\"']" (or body ""))]
    (mapv second hrefs)))

(defn- absolute [base href]
  (cond
    (str/blank? href) nil
    (str/starts-with? href "#") nil
    (str/starts-with? href "javascript:") nil
    (str/starts-with? href "mailto:") nil
    (re-find #"^[a-zA-Z][a-zA-Z0-9+.-]*://" href) href
    (str/starts-with? href "//") (str (:scheme (core/target-origin base)) ":" href)
    (str/starts-with? href "/") (let [{:keys [scheme host port]} (core/target-origin base)]
                                  (str scheme "://" host
                                       (when (and port
                                                  (not= port (case scheme "https" "443" "80")))
                                         (str ":" port))
                                       href))
    :else (let [{:keys [scheme host port path]} (core/target-origin base)]
            (str scheme "://" host ":" port
                 (or (some-> path (subs 0 (max 0 (dec (count path))))) "" )
                 "/" href))))

(defn extract-candidates
  "In-scope, normalized, deduped candidate URLs found in one response."
  [base-url body]
  (->> (extract-links body)
       (map (fn [h] (some->> h (absolute base-url) core/normalize-url)))
       (remove nil?)
       (filter #(core/same-origin? base-url %))
       distinct
       vec))

(defn spider
  "Breadth-first crawl within the target origin.

  opts:
    :max-pages   hard cap on fetched pages (default 50)
    :fetch-fn    request-map -> response-map (required; the injected effect)
  Returns {:pages [...response maps] :visited #{urls} :queue-drained? bool}"
  [{:keys [seed-url fetch-fn max-pages] :or {max-pages 50}}]
  (loop [queue (into clojure.lang.PersistentQueue/EMPTY [seed-url])
         visited #{}
         pages []]
    (if (or (empty? queue) (>= (count pages) max-pages))
      {:pages pages :visited visited :queue-drained? (empty? queue)}
      (let [url (peek queue)
            rest (pop queue)]
        (if (or (contains? visited url) (not (core/same-origin? seed-url url)))
          (recur rest visited pages)
          (let [resp (fetch-fn {:method "GET" :url url :headers {} :body nil})
                resp (assoc resp :url url)
                new (extract-candidates seed-url (get resp :body ""))]
            (recur (reduce conj rest new)
                   (conj visited url)
                   (conj pages resp))))))))
