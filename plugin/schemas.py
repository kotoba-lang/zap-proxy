"""zap-proxy plugin tool schemas — what the LLM reads to decide when to call.

Three tools, mirroring the decision core's tiers:
- zap_scan        passive-only scan of one target URL (safe default)
- zap_scan_rules  list the built-in rule registry (8 rules, IPA/OWASP mapped)
- zap_scan_active active (intrusive) scan — requires explicit allow_active=true
  AND a target recorded in zap_proxy_targets (own-host gate is enforced in
  tools.py, not left to the model's judgment).
"""
from __future__ import annotations

ZAP_SCAN = {
    "name": "zap_scan",
    "description": (
        "Run a passive (non-intrusive) DAST scan of a target URL using the "
        "kotoba-lang/zap-proxy decision core (clean-room ZAP equivalent). Checks "
        "security headers, cookie flags, and sensitive-info disclosure. Only "
        "targets recorded in zap_proxy_targets config are allowed — third-party "
        "hosts are refused. Returns a findings list with rule ids, severities, "
        "and evidence."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "URL to scan, e.g. http://localhost:8080. Must be in zap_proxy_targets.",
            },
            "max_pages": {
                "type": "integer",
                "description": "Spider page cap (default 50).",
            },
        },
        "required": ["target"],
    },
}

ZAP_SCAN_ACTIVE = {
    "name": "zap_scan_active",
    "description": (
        "Run an ACTIVE (intrusive) DAST scan — injects detection payloads "
        "(SQLi, XSS, command injection, path traversal, CRLF) into query "
        "parameters. Only for targets explicitly allowed, and only with "
        "allow_active=true in the target's config entry. Detection is "
        "evidence-based (error reflection, marker arithmetic) — no destructive "
        "payloads. This is a defense-side diagnostic tool for hosts you control."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "URL to scan. Must be in zap_proxy_targets with allow_active: true.",
            },
            "max_pages": {
                "type": "integer",
                "description": "Spider page cap (default 50).",
            },
        },
        "required": ["target"],
    },
}

ZAP_SCAN_RULES = {
    "name": "zap_scan_rules",
    "description": (
        "List the zap-proxy rule registry: rule id, kind (passive/active), "
        "severity, and the IPA「ウェブ健康診断仕様」/ OWASP WSTG item each rule "
        "maps to. Use this to explain what a scan covers before running one."
    ),
    "parameters": {"type": "object", "properties": {}, "required": []},
}

SCHEMAS = [ZAP_SCAN, ZAP_SCAN_ACTIVE, ZAP_SCAN_RULES]
