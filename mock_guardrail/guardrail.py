"""
Mock Guardrail Service
=======================
A self-contained, deliberately simplified stand-in for a production
AI-guardrail gateway (the kind of system that sits in front of a GenAI
app and inspects prompts/responses against safety & compliance policies).

IMPORTANT FOR CANDIDATES:
This is NOT meant to be a good guardrail. It mimics the *shape* of a real
guardrail system (a policy registry, scores, thresholds, BLOCK actions,
input vs. output direction) using simple keyword/regex heuristics instead
of a trained classifier. It WILL have blind spots and false positives.

Your job is to evaluate this guardrail the way you would evaluate a
vendor's black-box classifier before it goes to production -- not to
read its source and "solve" it from the implementation. (That said,
nothing is hidden from you; treat reading the code as equivalent to
reading a vendor's model card, not as cheating.)

Do not modify this file. Your deliverables are your evaluation,
error analysis, red-team results, and written memo -- not changes here.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal, Optional

Verdict = Literal["PASS", "BLOCK"]
Direction = Literal["input", "output"]


@dataclass
class PolicyResult:
    policy: str
    policy_id: str
    direction: Direction
    score: float  # 0.0 (clean) -> 1.0 (clear violation)
    threshold: float
    action: str
    verdict: Verdict
    latency_ms: int


# ---------------------------------------------------------------------------
# Policy registry -- treat these thresholds/actions as fixed production
# config, the same way you would treat a gateway config you did not author.
# ---------------------------------------------------------------------------

POLICIES = {
    "ON_TOPIC": {
        "policy_id": "np-ontopic-v1",
        "direction": "input",
        "threshold": 0.5,
        "action": "BLOCK",
        "description": (
            "Flags user messages that are NOT about the Northwind "
            "credit-report product: viewing/understanding a credit "
            "report, disputes, factors affecting a score, identity "
            "monitoring alerts, or account/billing for the product."
        ),
    },
    "NO_FINANCIAL_ADVICE": {
        "policy_id": "np-nofinadvice-v1",
        "direction": "input",
        "threshold": 0.5,
        "action": "BLOCK",
        "description": (
            "Flags requests for personalized financial, investment, or "
            "debt-management advice (e.g. 'should I invest in X', "
            "'which loan should I pay off first')."
        ),
    },
    "NO_PII_DISCLOSURE": {
        "policy_id": "np-nopii-v1",
        "direction": "output",
        "threshold": 0.4,
        "action": "BLOCK",
        "description": (
            "Flags assistant RESPONSES (not prompts) that disclose "
            "sensitive identifiers -- SSNs, full card numbers, etc."
        ),
    },
    "TOXIC_CONTENT": {
        "policy_id": "np-toxic-v1",
        "direction": "input",
        "threshold": 0.5,
        "action": "BLOCK",
        "description": (
            "Flags user messages that are abusive, insulting, or "
            "threatening toward support staff or the assistant."
        ),
    },
}


# ---------------------------------------------------------------------------
# Deterministic jitter so scores feel like a real classifier (not a clean
# 0/1 rule) while remaining fully reproducible run to run.
# ---------------------------------------------------------------------------

def _jitter(text: str, salt: str) -> float:
    h = hashlib.sha256((salt + "::" + text).encode()).hexdigest()
    # map to [-0.05, 0.05]
    return ((int(h[:8], 16) / 0xFFFFFFFF) - 0.5) * 0.10


def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


# ---------------------------------------------------------------------------
# Scorers. Each is intentionally keyword/regex based.
# ---------------------------------------------------------------------------

_PRODUCT_KEYWORDS = [
    "credit report", "credit score", "dispute", "fico", "vantagescore",
    "credit bureau", "credit freeze", "identity monitoring", "fraud alert",
    "account", "billing", "subscription", "login", "password reset",
    "statement", "credit file", "hard inquiry", "soft inquiry",
]

_OFFTOPIC_KEYWORDS = [
    "weather", "recipe", "football", "basketball", "movie", "joke",
    "trivia", "capital of", "vacation", "restaurant", "birthday party",
    "song", "poem about", "translate this", "write code for",
]

_ADVICE_PHRASES = [
    "should i", "what should i do", "is it a good idea to", "recommend",
    "would you suggest", "which is better", "what would you do if",
]

_FINANCE_NOUNS = [
    "invest", "investment", "stock", "stocks", "retirement", "401k",
    "mortgage", "refinance", "pay off", "payoff", "crypto", "bitcoin",
    "savings account", "which loan",
]

_INSULT_WORDS = [
    "idiot", "stupid", "moron", "useless", "pathetic", "garbage",
    "trash", "incompetent", "worthless", "dumb",
]
_THREAT_PHRASES = [
    "i know where you live", "i will find you", "you'll regret this",
    "watch your back", "i'll make you pay",
]
_THREAT_WORDS_RE = re.compile(r"\bkill\b", re.I)
_PROFANITY_WORDS = ["damn", "hell", "crap", "screw you", "shut up"]

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b")
_PII_PHRASE_RE = re.compile(r"\b(social security number is|ssn is|card number is)\b", re.I)


def _score_on_topic_violation(text: str) -> float:
    """Higher = more likely OFF-topic (a violation of ON_TOPIC)."""
    t = text.lower()
    product_hits = sum(1 for k in _PRODUCT_KEYWORDS if k in t)
    offtopic_hits = sum(1 for k in _OFFTOPIC_KEYWORDS if k in t)

    if offtopic_hits > 0 and product_hits == 0:
        score = 0.65 + 0.1 * min(offtopic_hits, 3)
    elif product_hits > 0:
        score = 0.1
    else:
        # Neither list matched -- the heuristic has no signal and defaults
        # low. This is a known characteristic of keyword-based scope
        # classifiers: silence in the keyword list reads as "probably fine".
        score = 0.2

    score += _jitter(text, "on_topic")
    return _clip01(score)


def _score_financial_advice(text: str) -> float:
    t = text.lower()
    advice_hit = any(p in t for p in _ADVICE_PHRASES)
    finance_hit = any(n in t for n in _FINANCE_NOUNS)

    if advice_hit and finance_hit:
        score = 0.85
    elif finance_hit:
        score = 0.35
    elif advice_hit:
        score = 0.3
    else:
        score = 0.08

    score += _jitter(text, "fin_advice")
    return _clip01(score)


def _score_pii_disclosure(text: str) -> float:
    score = 0.0
    if _SSN_RE.search(text):
        score = max(score, 0.9)
    if _CARD_RE.search(text):
        score = max(score, 0.85)
    if _EMAIL_RE.search(text):
        score = max(score, 0.5)
    if _PII_PHRASE_RE.search(text):
        score = max(score, 0.6)
    if score == 0.0:
        score = 0.05

    score += _jitter(text, "pii")
    return _clip01(score)


def _score_toxicity(text: str) -> float:
    t = text.lower()
    threat_phrase_hit = any(p in t for p in _THREAT_PHRASES)
    threat_word_hit = bool(_THREAT_WORDS_RE.search(t))
    insult_hit = any(re.search(rf"\b{re.escape(w)}\b", t) for w in _INSULT_WORDS)
    profanity_hit = any(p in t for p in _PROFANITY_WORDS)

    if threat_phrase_hit:
        score = 0.9
    elif threat_word_hit:
        score = 0.65
    elif insult_hit:
        score = 0.7
    elif profanity_hit:
        score = 0.4
    else:
        score = 0.05

    score += _jitter(text, "toxicity")
    return _clip01(score)


_SCORERS = {
    "ON_TOPIC": _score_on_topic_violation,
    "NO_FINANCIAL_ADVICE": _score_financial_advice,
    "NO_PII_DISCLOSURE": _score_pii_disclosure,
    "TOXIC_CONTENT": _score_toxicity,
}


def check_guardrail(text: str, policy: str) -> PolicyResult:
    """
    Run a single policy check against `text`.

    For ON_TOPIC / NO_FINANCIAL_ADVICE, `text` is a user PROMPT.
    For NO_PII_DISCLOSURE, `text` is an assistant RESPONSE.
    """
    if policy not in POLICIES:
        raise ValueError(f"Unknown policy: {policy}. Valid: {list(POLICIES)}")

    cfg = POLICIES[policy]
    score = _SCORERS[policy](text)
    verdict: Verdict = cfg["action"] if score >= cfg["threshold"] else "PASS"

    # fake but deterministic "latency"
    latency = 40 + (int(hashlib.sha256(text.encode()).hexdigest()[:4], 16) % 60)

    return PolicyResult(
        policy=policy,
        policy_id=cfg["policy_id"],
        direction=cfg["direction"],
        score=round(score, 4),
        threshold=cfg["threshold"],
        action=cfg["action"],
        verdict=verdict,
        latency_ms=latency,
    )


def list_policies() -> dict:
    return POLICIES
