#!/usr/bin/env python3
"""zap-scanner daily probe: verify the zap-proxy decision core is runnable
and report what it WOULD scan. No network scan happens here — this is the
observe step that proves the toolchain is alive and lists the in-scope
targets from the own-host ledger. The agent-run scan (with real transport)
is a separate, operator-approved job."""
import json, subprocess, sys, os, datetime

HOME = os.path.expanduser("~")
REPO = f"{HOME}/github/com-junkawasaki/orgs/kotoba-lang/zap-proxy"
out = {"date": datetime.datetime.now().isoformat(timespec="seconds"), "checks": []}

def check(name, ok, detail):
    out["checks"].append({"name": name, "ok": bool(ok), "detail": str(detail)[:300]})

# 1. repo present and pinned
r = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True)
check("zap-proxy checkout", r.returncode == 0, r.stdout.strip() or r.stderr.strip())

# 2. decision core loads (no network — pure require + rules registry read)
core_code = (
    "(require '[kotoba.zap-proxy.cli :as cli]) "
    "(def rules (read-string (slurp \"resources/zap_proxy/rules/rules.edn\"))) "
    "(println :RULES (count rules))"
)
r = subprocess.run(["clojure", "-M", "-e", core_code], capture_output=True, text=True, cwd=REPO, timeout=240)
rules_ok = ":RULES 8" in r.stdout
check("decision core loads + rules registry", r.returncode == 0 and rules_ok,
      "out=" + r.stdout.strip()[-120:] + " err=" + (r.stderr.strip()[-200:] if r.returncode else ""))

# 3. self-scan against a local mock (proves the pipeline end-to-end without network)
mock_code = (
    "(require '[kotoba.zap-proxy.cli :as cli]) "
    "(def mock (fn [{:keys [url]}] {:status 200 :headers {\"set-cookie\" \"sid=1; Path=/\"} "
    ":body \"<html><a href='/x?q=1'>x</a> password: hunter2</html>\"})) "
    "(def doc (cli/scan {:target \"http://t.local/\" :fetch-fn mock :active? false})) "
    "(println :TOTAL (:report/total doc))"
)
r = subprocess.run(["clojure", "-M", "-e", mock_code], capture_output=True, text=True, cwd=REPO, timeout=240)
total_ok = ":TOTAL " in r.stdout and any(ch.isdigit() for ch in r.stdout.split(":TOTAL")[-1])
check("mock scan pipeline", r.returncode == 0 and total_ok,
      "out=" + r.stdout.strip()[-120:] + " err=" + (r.stderr.strip()[-200:] if r.returncode else ""))

# 4. in-scope targets: own-host ledger — listed, not scanned
ledger = f"{HOME}/github/com-junkawasaki/manifest/origin-domains.edn"
check("own-host ledger present", os.path.exists(ledger), ledger if os.path.exists(ledger) else "missing")

out["verdict"] = "green" if all(c["ok"] for c in out["checks"]) else "red"
print(json.dumps(out, ensure_ascii=False, indent=1))
sys.exit(0 if out["verdict"] == "green" else 1)
