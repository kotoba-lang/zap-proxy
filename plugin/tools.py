"""zap-proxy plugin tool handlers.

Architecture: the decision core is pure .cljc in the zap-proxy repo (judgment,
no I/O); this plugin is the host side. It:
  1. enforces the own-host gate in PYTHON, before any subprocess runs —
     the model cannot talk its way past it;
  2. shells out to `clojure -M -m kotoba.zap-proxy.plugin-entry` with the
     request on stdin (EDN), reads the report on stdout (EDN);
  3. never passes raw shell strings — argv is a fixed list.

Transport note: the clojure entry point uses its own injected HTTP effects
(java.net.http by default) — the plugin never opens sockets itself.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_REPO = Path(
    os.environ.get(
        "ZAP_PROXY_REPO",
        str(Path.home() / "github/com-junkawasaki/orgs/kotoba-lang/zap-proxy"),
    )
)

# ---- own-host gate ---------------------------------------------------------
# Sources, in order: ZAP_PROXY_TARGETS env (comma-separated "url[:active]"),
# then plugin config settings.zap_proxy_targets (list of {url, allow_active}).
# A target is scannable iff its ORIGIN (scheme://host:port) matches an entry.

def _load_targets(ctx: Any = None) -> Dict[str, Dict[str, Any]]:
    targets: Dict[str, Dict[str, Any]] = {}
    # 1) ctx.get_config (plugin-relative settings read — the real ctx API).
    if ctx is not None:
        try:
            raw = ctx.get_config("zap_proxy_targets")
            if isinstance(raw, list):
                for t in raw:
                    if isinstance(t, dict) and t.get("url"):
                        targets.setdefault(_origin(t["url"]), {"allow_active": bool(t.get("allow_active"))})
        except Exception:
            pass
    # 2) direct config.yaml read (survives gateways that don't pass settings).
    if not targets:
        try:
            import yaml  # hermes ships pyyaml
            cfg_path = os.environ.get("HERMES_CONFIG") or os.path.expanduser("~/.hermes/config.yaml")
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f) or {}
            entries = ((cfg.get("plugins") or {}).get("entries") or {})
            for key in ("hermes-zap-proxy", "zap-proxy"):
                raw = ((entries.get(key) or {}).get("settings") or {}).get("zap_proxy_targets") or []
                for t in raw:
                    if isinstance(t, dict) and t.get("url"):
                        targets.setdefault(_origin(t["url"]), {"allow_active": bool(t.get("allow_active"))})
        except Exception as e:
            logger.debug("config.yaml target read failed: %s", e)
    # 3) env override (comma-separated url[:active]).
    env = os.environ.get("ZAP_PROXY_TARGETS", "")
    for entry in env.split(","):
        entry = entry.strip()
        if not entry:
            continue
        active = False
        if entry.endswith(":active"):
            active, entry = True, entry[: -len(":active")]
        targets.setdefault(_origin(entry), {"allow_active": active})
    return targets


def _origin(url: str) -> str:
    u = url if "://" in url else "http://" + url
    scheme, rest = u.split("://", 1)
    hostport = rest.split("/", 1)[0]
    if ":" not in hostport:
        hostport += ":443" if scheme == "https" else ":80"
    return f"{scheme.lower()}://{hostport.lower()}"


def _gate(ctx: Any, target: str, active: bool) -> Optional[str]:
    """Return a refusal reason, or None when allowed."""
    targets = _load_targets(ctx or {})
    if not targets:
        return (
            "No zap_proxy_targets configured. Add targets to plugin settings "
            "(plugins.entries.hermes-zap-proxy.settings.zap_proxy_targets) or set "
            "ZAP_PROXY_TARGETS='http://host:port[,http://host2:active]'. "
            "This gate exists so the agent cannot scan third-party hosts."
        )
    entry = targets.get(_origin(target))
    if entry is None:
        allowed = ", ".join(sorted(targets))
        return f"Target origin {_origin(target)} is not in zap_proxy_targets (allowed: {allowed}). Refusing to scan hosts outside the ledger."
    if active and not entry.get("allow_active"):
        return (
            f"Target {_origin(target)} is registered without allow_active. "
            "Active scan refused — record allow_active: true for this target first."
        )
    return None


# ---- subprocess bridge ------------------------------------------------------

def _run_core(edn_request: str) -> Dict[str, Any]:
    if not _REPO.exists():
        return {"error": f"zap-proxy repo not found at {_REPO}"}
    clojure = shutil.which("clojure")
    if not clojure:
        return {"error": "clojure CLI not on PATH"}
    try:
        r = subprocess.run(
            [clojure, "-M", "-m", "kotoba.zap-proxy.plugin-entry"],
            input=edn_request,
            capture_output=True,
            text=True,
            cwd=str(_REPO),
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return {"error": "scan timed out after 600s"}
    if r.returncode != 0:
        return {"error": "scan failed", "stderr": r.stderr[-500:]}
    return {"raw": r.stdout}


def _to_jsonable(raw: str) -> Any:
    """Best-effort EDN->JSON for the chat surface: numbers/counts are extracted
    by the clojure entry (it prints a :json line); full EDN is included for
    the agent to read."""
    return {"report_edn": raw}


# ---- tool handlers ----------------------------------------------------------
# The Hermes registry invokes handlers as handler(args_dict) — one positional
# dict of the tool-call arguments (see tools/registry.py dispatch). Accept that
# form natively while still supporting direct keyword calls in tests.

def _extract(args: Any, kwargs: Dict[str, Any]) -> tuple:
    """Tool args may arrive as one positional dict (registry dispatch) or as
    keywords (direct calls/tests). Normalize to (target, max_pages). The
    handler forwards its own keyword defaults as None — only non-None
    keyword values take precedence over the args dict."""
    merged: Dict[str, Any] = dict(args) if isinstance(args, dict) else {}
    for k, v in kwargs.items():
        if v is not None:
            merged[k] = v
    return str(merged.get("target") or ""), int(merged.get("max_pages") or 50)


def zap_scan(args: Any = None, target: Any = None, max_pages: Any = None, **kwargs: Any) -> str:
    target, max_pages = _extract(args, {"target": target, "max_pages": max_pages, **kwargs})
    refusal = _gate(None, target, active=False)
    if refusal:
        return json.dumps({"refused": refusal})
    edn = (f'{{:target "{target}" :active? false :max-pages {int(max_pages)} '
           f':transport :java-http}}')
    result = _run_core(edn)
    if "error" in result:
        return json.dumps(result)
    return json.dumps({"target": target, "mode": "passive", **_to_jsonable(result["raw"])})


def zap_scan_active(args: Any = None, target: Any = None, max_pages: Any = None, **kwargs: Any) -> str:
    target, max_pages = _extract(args, {"target": target, "max_pages": max_pages, **kwargs})
    refusal = _gate(None, target, active=True)
    if refusal:
        return json.dumps({"refused": refusal})
    edn = (f'{{:target "{target}" :active? true :max-pages {int(max_pages)} '
           f':transport :java-http}}')
    result = _run_core(edn)
    if "error" in result:
        return json.dumps(result)
    return json.dumps({"target": target, "mode": "active", **_to_jsonable(result["raw"])})


def zap_scan_rules(args: Any = None, **_: Any) -> str:
    if not _REPO.exists():
        return json.dumps({"error": f"zap-proxy repo not found at {_REPO}"})
    rules_file = _REPO / "resources/zap_proxy/rules/rules.edn"
    try:
        text = rules_file.read_text()
    except OSError as e:
        return json.dumps({"error": f"cannot read rules registry: {e}"})
    # crude but honest: hand the registry to the agent as EDN text
    return json.dumps({"registry_edn": text})
