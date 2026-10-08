#!/usr/bin/env node
// zap-proxy Node transport: emits EDN the decision core consumes.
// Usage: node zap_fetch.js <url>   ->  {:status 200 :headers {:set-cookie ["a" "b"]} :body "..."}
const u = process.argv[2] || "http://127.0.0.1";
const esc = (s) =>
  '"' +
  String(s)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\x08/g, "\\b")
    .replace(/\t/g, "\\t")
    .replace(/\n/g, "\\n")
    .replace(/\f/g, "\\f")
    .replace(/\r/g, "\\r")
    .replace(/'/g, "") // drop apostrophes: EDN strings are double-quoted, ' is safe to omit
    .replace(/[^\x20-\x7e]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")) +
  '"';
const val = (v) => (Array.isArray(v) ? "[" + v.map(esc).join(" ") + "]" : esc(v));
const h = /^https/.test(u) ? require("https") : require("http");
let done = false;
const fin = (r) => {
  if (done) return;
  done = true;
  const hdr =
    "{" +
    Object.entries(r.headers || {})
      .filter(([k]) => k)
      .map(([k, v]) => ":" + k.toLowerCase() + " " + val(v))
      .join(" ") +
    "}";
  process.stdout.write("{:status " + r.statusCode + " :headers " + hdr + " :body " + esc(r.body) + "}");
};
const req = h.request(u, { timeout: 15000 }, (res) => {
  let d = [];
  res.on("data", (c) => d.push(c));
  res.on("end", () => fin({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(d).toString("utf8") }));
});
req.on("error", (e) => {
  done = true;
  process.stdout.write("{:status 0 :headers {} :body " + esc(String(e)) + "}");
});
req.on("timeout", () => req.destroy(new Error("timeout")));
req.end();
