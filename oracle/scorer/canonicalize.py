"""Path canonicalization + vulnerability-class inference.

This is the oracle's OWN canonicalizer — deliberately NOT a copy of agent-smith's
internal ``core/coverage._normalize_path`` (verified: that one leaves ``{account_number}``
vs ``{id}`` un-unified and keeps query strings, so it fails as a cross-system join key).

Two jobs:
  * ``canonicalize_path`` — collapse any host, query string, and id-like / placeholder
    path segment so ``/check_balance/8206264376`` and ``/check_balance/{account_number}``
    map to the same key.
  * class inference — coarse vulnerability-class labels for a finding (from its text)
    and for a ground-truth entry (from its id / owasp), used to gate matches so a BOLA
    finding on ``/check_balance`` does not get mis-mapped onto the SQLi id for the same path.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

# Path segments that introduce an object id — the segment AFTER one of these is
# always collapsed to {id}, regardless of whether it is numeric, a UUID, or an
# LLM-authored placeholder like {account_number}.
_COLLECTION_NOUNS = {
    "check_balance", "transactions", "account", "accounts", "user", "users",
    "payments", "payment", "virtual-cards", "billers", "by-category", "merchant_id",
    "merchants", "approve_loan", "delete_account", "toggle_suspension", "card",
    "loan", "profile", "bill-payments",
}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_PLACEHOLDER_RE = re.compile(r"^\{.*\}$")            # {id}, {account_number}, ...
_DIGITS_RE = re.compile(r"^\d+$")
_LONGNUM_RE = re.compile(r"^[0-9]{5,}$")             # account numbers etc.


def _is_id_like(token: str) -> bool:
    if not token:
        return False
    if _PLACEHOLDER_RE.match(token):
        return True
    if _DIGITS_RE.match(token):
        return True
    if _LONGNUM_RE.match(token):
        return True
    if _UUID_RE.match(token):
        return True
    return False


def canonicalize_path(url_or_path: str) -> str:
    """Return a stable canonical path: host/query stripped, ids collapsed to {id}.

    >>> canonicalize_path("http://x/check_balance/8206264376")
    '/check_balance/{id}'
    >>> canonicalize_path("/check_balance/{account_number}")
    '/check_balance/{id}'
    >>> canonicalize_path("http://x/api/transactions?account_number=1")
    '/api/transactions'
    """
    if not url_or_path:
        return ""
    raw = url_or_path.strip()
    if "://" in raw:
        parts = urlsplit(raw)
        path = parts.path or "/"
    else:
        # strip a possible leading host:port or bare query
        path = raw.split("?", 1)[0].split("#", 1)[0]
    path = path.split("?", 1)[0].split("#", 1)[0]
    path = path.lower()
    if not path.startswith("/"):
        path = "/" + path
    tokens = path.split("/")
    out = []
    for i, tok in enumerate(tokens):
        prev = tokens[i - 1] if i > 0 else ""
        if i == 0 or tok == "":
            out.append(tok)
            continue
        if _is_id_like(tok) or (prev in _COLLECTION_NOUNS):
            out.append("{id}")
        else:
            out.append(tok)
    canon = "/".join(out)
    if len(canon) > 1 and canon.endswith("/"):
        canon = canon[:-1]
    return canon or "/"


# --------------------------------------------------------------------------- classes
# Coarse classes used only for match-gating. Keyword lists are ordered most- to
# least-specific; the FIRST family with a keyword hit wins as the primary class,
# but we return the full set of hits so a finding can be compatible with several ids.
_CLASS_KEYWORDS = [
    ("ai-injection", ["prompt injection", "llm01", "jailbreak", "ignore previous", "instructed to comply"]),
    ("ai-leak",      ["system prompt", "llm07", "system-info", "system information disclosure", "system info"]),
    ("ai-agency",    ["llm06", "excessive agency", "database access via", "ai chatbot", "broken authorization"]),
    ("ai-data",      ["llm02", "sent to external", "external llm", "sensitive user data"]),
    ("ratelimit",    ["rate limit bypass", "rate-limit bypass", "x-forwarded-for", "x-real-ip", "header spoof"]),
    ("metadata",     ["imds", "metadata", "iam credential", "169.254.169.254", "security-credentials", "instance metadata"]),
    ("ssrf",         ["ssrf", "server-side request", "request forgery"]),
    ("cors",         ["cors", "access-control-allow-origin", "arbitrary origin"]),
    ("headers",      ["security headers", "missing header", "x-frame-options", "content-security-policy", "csp header"]),
    ("xss",          ["xss", "cross-site scripting", "cross site scripting"]),
    ("massassign",   ["mass assignment", "bopla", "is_admin", "arbitrary field", "excessive data exposure"]),
    ("bola",         ["bola", "idor", "broken object", "broken object level", "any account", "any user", "bfla", "broken function level"]),
    ("sqli",         ["sql injection", "sqli", "sql-injection"]),
    ("jwt",          ["jwt", "json web token", "token forgery", "signing secret", "missing expiry", "none algorithm", "alg none"]),
    ("fileupload",   ["file upload", "arbitrary file", "unrestricted upload", "no file type"]),
    ("businesslogic", ["negative transfer", "negative amount", "negative loan", "phantom transaction", "race condition",
                       "double spend", "business logic", "value abuse", "zero amount"]),
    ("pin",          ["reset pin", "pin reset", "guessable pin", "reset-password pin", "4-digit pin", "3-digit pin", "pin exposed", "pin disclosed"]),
    ("brute",        ["brute force", "no lockout", "account lockout", "credential stuffing", "password spray"]),
    ("admin",        ["admin panel", "sup3r_s3cr3t", "hidden admin", "create_admin", "create admin", "admin account creation"]),
    ("secrets",      ["plaintext", "hardcoded", "hard-coded", "cleartext password", "secret_key", "secret key"]),
    ("exposure",     ["debug/users", "debug information", "debug mode", "verbose error", "stack trace", "swagger", "openapi", "information disclosure", "internal endpoint", "internal/secret"]),
    ("cookie",       ["cookie", "samesite", "secure flag", "httponly"]),
    ("usernameenum", ["username enumeration", "user enumeration", "account enumeration"]),
]

# Map a ground-truth id to its primary + allowed classes. Some ids legitimately
# accept more than one class (e.g. create_admin is both injection and access).
_ID_CLASS = {
    "VB-SQLI-LOGIN": {"sqli"},
    "VB-SQLI-CHECK-BALANCE": {"sqli"},
    "VB-SQLI-TRANSACTIONS-PATH": {"sqli"},
    "VB-SQLI-API-TRANSACTIONS": {"sqli"},
    "VB-SQLI-CREATE-ADMIN": {"sqli", "admin", "bola"},
    "VB-SQLI-BILLERS": {"sqli"},
    "VB-SQLI-VIRTUAL-CARDS": {"sqli"},
    "VB-SQLI-MERCHANT": {"sqli"},
    "VB-SQLI-GRAPHQL": {"sqli"},
    "VB-JWT-NONE-ALG": {"jwt"},
    "VB-JWT-WEAK-SECRET": {"jwt", "secrets"},
    "VB-JWT-NO-EXPIRY": {"jwt"},
    "VB-JWT-TOKEN-MULTILOC": {"jwt"},
    "VB-IDOR-API-V3-USER": {"bola"},
    "VB-BOLA-CARD-OPS": {"bola"},
    "VB-BOLA-MERCHANT-PAYMENT": {"bola"},
    "VB-BOLA-TXN-NOAUTH": {"bola"},
    "VB-MASSASSIGN-REGISTER": {"massassign"},
    "VB-MASSASSIGN-CARD-LIMIT": {"massassign"},
    "VB-MASSASSIGN-CARD-FUND-RATE": {"massassign"},
    "VB-WEAK-PIN-RESET": {"pin", "brute"},
    "VB-PIN-DISCLOSURE": {"pin", "exposure"},
    "VB-NO-LOCKOUT-LOGIN": {"brute"},
    "VB-USERNAME-ENUM": {"usernameenum"},
    "VB-SSRF-PROFILE-URL": {"ssrf"},
    "VB-SSRF-INTERNAL-SECRET": {"ssrf", "exposure", "secrets"},
    "VB-SSRF-CLOUD-METADATA": {"metadata", "ssrf"},
    "VB-STORED-XSS": {"xss"},
    "VB-REFLECTED-XSS": {"xss"},
    "VB-FILE-UPLOAD": {"fileupload"},
    "VB-BL-NEG-TRANSFER": {"businesslogic"},
    "VB-BL-ZERO-TRANSFER": {"businesslogic"},
    "VB-BL-NEG-LOAN": {"businesslogic"},
    "VB-BL-RACE-TRANSFER": {"businesslogic"},
    "VB-PREDICTABLE-CARD": {"businesslogic", "secrets"},
    "VB-DEBUG-USERS": {"exposure", "bola"},
    "VB-HIDDEN-ADMIN": {"admin", "exposure"},
    "VB-PLAINTEXT-SECRETS": {"secrets"},
    "VB-HARDCODED-SECRETS": {"secrets"},
    "VB-SWAGGER-EXPOSURE": {"exposure"},
    "VB-VERBOSE-ERRORS": {"exposure"},
    "VB-COOKIE-FLAGS": {"cookie"},
    "VB-CORS-WILDCARD": {"cors"},
    "VB-MISSING-HEADERS": {"headers"},
    "VB-AI-PROMPT-INJECTION": {"ai-injection"},
    "VB-AI-SYSTEM-PROMPT-LEAK": {"ai-leak"},
    "VB-AI-EXCESSIVE-AGENCY": {"ai-agency", "ai-injection"},
    "VB-AI-SENSITIVE-DATA-EXT": {"ai-data"},
    "VB-AI-RATE-LIMIT-BYPASS": {"ratelimit"},
    "VB-SQLITE-LEGACY": {"sqli"},
    "EXT-DO-METADATA-SSRF": {"metadata", "ssrf"},
    "EXT-K8S-PRIVESC-SA": {"exposure"},
    "EXT-K8S-PRIVILEGED-POD": {"exposure"},
    "EXT-K8S-KUBELET-RO": {"exposure"},
    "EXT-KONG-ADMIN-EXPOSED": {"exposure"},
    "EXT-AI-GRADED-JAILBREAK": {"ai-injection"},
}

# Negative-result phrasing — a finding mapped to a vuln but actually reporting
# FAILURE to exploit (the IMDS false-negative is the canonical example).
_NEGATIVE_RESULT_RE = re.compile(
    r"\b(no .* (obtained|found|present)|not vulnerable|unable to|could not|"
    r"enforced, no|no iam credentials|appears secure|properly configured)\b", re.I
)


def infer_finding_classes(text: str) -> set[str]:
    """Return the set of coarse vuln classes a finding's text is compatible with."""
    t = text.lower()
    hits = {fam for fam, kws in _CLASS_KEYWORDS if any(k in t for k in kws)}
    return hits


def gt_classes(gt_id: str) -> set[str]:
    return _ID_CLASS.get(gt_id, set())


def is_negative_result(text: str) -> bool:
    return bool(_NEGATIVE_RESULT_RE.search(text or ""))
