#!/usr/bin/env python3
"""Identify which anti-bot / WAF product produced an HTTP response.

Usage:
    python detect.py https://example.com
    python detect.py https://example.com --json
    python detect.py https://example.com --verbose --timeout 20
    python detect.py --from-json saved-response.json     # no network at all

The interesting part of this file is ``VENDORS``: a single module-level list of
dicts holding every signature the tool knows about. Adding a vendor means adding
one entry to that list - no other code changes. See CONTRIBUTING.md.

``detect(status, headers, body)`` is a pure function with no I/O. Import it and
feed it responses from whatever HTTP client you already use.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0.0"

__all__ = [
    "VENDORS",
    "detect",
    "fetch",
    "format_report",
    "load_record",
    "normalize_headers",
    "FetchError",
    "STATE_BLOCK",
    "STATE_CHALLENGE",
    "STATE_CLEAR",
    "STATE_QUEUE",
    "STATE_UNKNOWN",
]

# --------------------------------------------------------------------------
# Response states
#
# A vendor being present is not the same thing as being blocked. A site can sit
# behind Cloudflare and still hand you a perfectly normal page. These states
# describe *this response*, not the site.
# --------------------------------------------------------------------------

STATE_CLEAR = "clear"          # looks like real content
STATE_CHALLENGE = "challenge"  # an interstitial / JS challenge is being served
STATE_BLOCK = "block"          # an outright denial
STATE_QUEUE = "queue"          # a virtual waiting room, not bot detection
STATE_UNKNOWN = "unknown"      # not enough information

# Precedence when several kinds of marker match at once.
_STATE_PRECEDENCE = (STATE_BLOCK, STATE_CHALLENGE, STATE_QUEUE)

# --------------------------------------------------------------------------
# Signature data
#
# Signal kinds:
#   header  name=<header name>            optional contains=<substring of value>
#   cookie  name=<cookie name>            optional mode="prefix" (default "exact")
#   body    contains=<substring>          matched case-insensitively
#   url     contains=<substring>          matched against final URL + redirect chain
#   status  codes=[int, ...]
#
# Optional per-signal key:
#   state   one of "block" / "challenge" / "queue" - set only on markers that
#           cannot appear on a normal content response.
#
# Weights (keep them honest, this is the whole value of the tool):
#   5  unique to this vendor, appears on any response from it
#   4  unique to this vendor, but only on a block/challenge response
#   3  strongly associated, small chance of collision
#   2  consistent with this vendor, shared with others
#   1  weak corroboration on its own (status codes, generic CDN headers)
#
# A "status" signal can never identify a vendor by itself. Every vendor sits
# behind a 403 at some point, so a vendor is only ever reported if at least one
# header, cookie, body or url signal matched; status codes only adjust the
# score of a vendor that was already identified some other way.
#
# A vendor also has to reach CONFIDENCE_MEDIUM before its markers are allowed to
# set the response state. One weight-2 phrase in the body is corroboration, not
# a verdict, and reporting "you are blocked" off the back of one is exactly the
# kind of confident wrongness this tool exists to argue against.
# --------------------------------------------------------------------------

VENDORS = [
    {
        "name": "Cloudflare",
        "slug": "cloudflare",
        "product": "Cloudflare WAF / Bot Management / Managed Challenge / Turnstile",
        "inspects": "TLS and HTTP/2 fingerprint, header order, JS challenge with "
                    "proof-of-work, per-request bot score",
        "notes": "The most common thing in front of a website is also the most "
                 "commonly misdiagnosed. Read the numeric error code in the body: "
                 "1020 is a WAF rule, 1015 is rate limiting, 1010 is a "
                 "browser-signature ban. Those are configuration decisions, not "
                 "challenges, and retrying does not clear them.",
        "next_step": (
            "Separate 'challenge' from 'firewall rule' before doing anything else. "
            "A challenge is transient and passable in a real browser; a 1020 is a "
            "rule someone wrote and will not clear on retry. If it is a challenge "
            "and you are permitted to collect this data, the usual approach is to "
            "pass it once in a real browser and then keep the session and the TLS "
            "fingerprint consistent."
        ),
        "signals": [
            {"kind": "header", "name": "cf-ray", "weight": 5},
            {"kind": "header", "name": "cf-mitigated", "weight": 5, "state": STATE_CHALLENGE},
            {"kind": "header", "name": "cf-cache-status", "weight": 2},
            {"kind": "header", "name": "server", "contains": "cloudflare", "weight": 2},
            {"kind": "cookie", "name": "__cf_bm", "weight": 4},
            {"kind": "cookie", "name": "cf_clearance", "weight": 4},
            {"kind": "cookie", "name": "__cflb", "weight": 2},
            {"kind": "body", "contains": "cdn-cgi/challenge-platform", "weight": 5,
             "state": STATE_CHALLENGE},
            {"kind": "body", "contains": "window._cf_chl_opt", "weight": 5,
             "state": STATE_CHALLENGE},
            # With the trailing dots, because "just a moment" on its own is a
            # phrase real pages use. The interstitial title is "Just a moment...".
            {"kind": "body", "contains": "just a moment...", "weight": 4,
             "state": STATE_CHALLENGE},
            {"kind": "body", "contains": "/cdn-cgi/l/chk_jschl", "weight": 4,
             "state": STATE_CHALLENGE},
            {"kind": "body", "contains": "challenges.cloudflare.com/turnstile", "weight": 4,
             "state": STATE_CHALLENGE},
            {"kind": "body", "contains": "attention required! | cloudflare", "weight": 5,
             "state": STATE_BLOCK},
            {"kind": "body", "contains": "sorry, you have been blocked", "weight": 4,
             "state": STATE_BLOCK},
            {"kind": "body", "contains": "error 1020", "weight": 4, "state": STATE_BLOCK},
            {"kind": "body", "contains": "error 1015", "weight": 4, "state": STATE_BLOCK},
            {"kind": "body", "contains": "error 1010", "weight": 4, "state": STATE_BLOCK},
            {"kind": "status", "codes": [403, 429, 503], "weight": 1},
        ],
    },
    {
        "name": "DataDome",
        "slug": "datadome",
        "product": "DataDome Bot Protection",
        "inspects": "TLS fingerprint, header order and casing, a device-fingerprint "
                    "JS payload, behavioural signals, IP reputation",
        "notes": "The block response is usually JSON, not HTML, and carries a "
                 "'url' field pointing at a captcha host. The response status is "
                 "configurable by the site operator, so do not key your logic on "
                 "the status code alone.",
        "next_step": (
            "Check whether you are getting the interstitial on every request or "
            "only after N requests. DataDome reacts strongly to request-rate and "
            "to header sets that do not match the claimed browser. If you are "
            "permitted to collect this data, reduce concurrency first and make "
            "sure your headers are internally consistent before anything else."
        ),
        "signals": [
            {"kind": "cookie", "name": "datadome", "weight": 5},
            {"kind": "header", "name": "x-datadome", "weight": 4},
            {"kind": "body", "contains": "captcha-delivery.com", "weight": 5,
             "state": STATE_CHALLENGE},
            {"kind": "body", "contains": "datadome", "weight": 2},
            {"kind": "status", "codes": [403], "weight": 1},
        ],
    },
    {
        "name": "PerimeterX (HUMAN)",
        "slug": "perimeterx",
        "product": "HUMAN Bot Defender, formerly PerimeterX",
        "inspects": "JS sensor payload, behavioural biometrics (pointer, key "
                    "timing), TLS fingerprint, IP reputation",
        "notes": "Block responses are frequently JSON containing appId, vid and "
                 "uuid rather than an HTML page. The app id looks like PX + a "
                 "short token and is stable per site, which makes it a reliable "
                 "identifier once you have seen it.",
        "next_step": (
            "Record the appId, vid and uuid from the block payload - they are the "
            "reference a site operator will ask for if you contact them. This "
            "product weights behavioural signals heavily, so a headless client "
            "that never moves a pointer is easy to separate from a human. If you "
            "need this data at volume, asking for API access is the realistic path."
        ),
        "signals": [
            {"kind": "cookie", "name": "_px3", "weight": 5},
            {"kind": "cookie", "name": "_pxvid", "weight": 4},
            {"kind": "cookie", "name": "pxcts", "weight": 4},
            {"kind": "cookie", "name": "_pxhd", "weight": 4},
            {"kind": "cookie", "name": "_pxcaptcha", "weight": 4, "state": STATE_CHALLENGE},
            {"kind": "body", "contains": "_pxAppId", "weight": 5},
            # Fields of the JSON block payload. The app id is always PX + token.
            {"kind": "body", "contains": '"appId":"PX', "weight": 5, "state": STATE_BLOCK},
            {"kind": "body", "contains": "jsClientSrc", "weight": 5},
            {"kind": "body", "contains": "px-cloud.net", "weight": 5},
            {"kind": "body", "contains": "px-cdn.net", "weight": 4},
            {"kind": "body", "contains": "perimeterx", "weight": 4},
            {"kind": "body", "contains": "access to this page has been denied", "weight": 4,
             "state": STATE_BLOCK},
            {"kind": "status", "codes": [403], "weight": 1},
        ],
    },
    {
        "name": "Akamai Bot Manager",
        "slug": "akamai",
        "product": "Akamai Bot Manager / Web Application Protector",
        "inspects": "A sensor payload POSTed by obfuscated JS, TLS and HTTP/2 "
                    "fingerprint, header order, request cadence",
        "notes": "The _abck cookie is the state machine. A widely reported "
                 "heuristic is that a value containing ~0~ means the sensor was "
                 "accepted and ~-1~ means it was not; treat that as a field "
                 "observation rather than documented behaviour, because the format "
                 "changes. Akamai also does soft responses: a 200 that is real "
                 "HTML but missing the data you wanted.",
        "next_step": (
            "Confirm you are actually blocked rather than being served a "
            "deliberately degraded response. Compare body length and a known "
            "in-page marker against a browser session. Akamai deny pages carry a "
            "'Reference #' - log it verbatim, it is what support will ask for."
        ),
        "signals": [
            {"kind": "cookie", "name": "_abck", "weight": 5},
            {"kind": "cookie", "name": "bm_sz", "weight": 5},
            {"kind": "cookie", "name": "ak_bmsc", "weight": 5},
            {"kind": "cookie", "name": "bm_sv", "weight": 4},
            {"kind": "cookie", "name": "bm_mi", "weight": 3},
            {"kind": "cookie", "name": "bm_s", "weight": 3},
            {"kind": "header", "name": "server", "contains": "akamaighost", "weight": 5},
            {"kind": "header", "name": "x-akamai-request-id", "weight": 4},
            {"kind": "body", "contains": "reference #", "weight": 3, "state": STATE_BLOCK},
            {"kind": "body", "contains": "you don't have permission to access", "weight": 2,
             "state": STATE_BLOCK},
            {"kind": "body", "contains": "akamai", "weight": 2},
            {"kind": "status", "codes": [403], "weight": 1},
        ],
    },
    {
        "name": "Imperva (Incapsula)",
        "slug": "imperva",
        "product": "Imperva Cloud WAF / Advanced Bot Protection, formerly Incapsula "
                   "and Distil",
        "inspects": "JS challenge producing a signed token cookie, TLS "
                    "fingerprint, IP reputation, request patterns",
        "notes": "Two generations coexist. Classic Incapsula sets visid_incap_* "
                 "and incap_ses_* and serves an _Incapsula_Resource script; "
                 "Advanced Bot Protection uses the reese84 token cookie obtained "
                 "from a JS interstitial. You may see either or both.",
        "next_step": (
            "Capture the 'Incapsula incident ID' - it maps to a specific rule on "
            "the operator's side and is the one piece of information that makes a "
            "support request actionable. If the interstitial is served on the "
            "first request from a clean IP, the trigger is more likely your client "
            "fingerprint than your behaviour."
        ),
        "signals": [
            {"kind": "header", "name": "x-iinfo", "weight": 5},
            {"kind": "header", "name": "x-cdn", "contains": "incapsula", "weight": 5},
            {"kind": "cookie", "name": "visid_incap_", "mode": "prefix", "weight": 5},
            {"kind": "cookie", "name": "incap_ses_", "mode": "prefix", "weight": 5},
            {"kind": "cookie", "name": "nlbi_", "mode": "prefix", "weight": 4},
            {"kind": "cookie", "name": "reese84", "weight": 5},
            {"kind": "body", "contains": "incapsula incident id", "weight": 5,
             "state": STATE_BLOCK},
            {"kind": "body", "contains": "_incapsula_resource", "weight": 5},
            {"kind": "body", "contains": "imperva", "weight": 3},
            {"kind": "status", "codes": [403], "weight": 1},
        ],
    },
    {
        "name": "Kasada",
        "slug": "kasada",
        "product": "Kasada Bot Defense",
        "inspects": "Client-side proof-of-work executed inside an obfuscated VM, "
                    "browser API probing, TLS fingerprint",
        "notes": "Kasada commonly answers a rejected request with HTTP 429 and a "
                 "very short or empty body. That is the single most misdiagnosed "
                 "response in this guide: people read 429, assume rate limiting, "
                 "add a sleep, and wait forever. A 429 with no Retry-After and no "
                 "rate-limit headers deserves a look at the x-kpsdk-* family.",
        "next_step": (
            "Check request and response headers for the x-kpsdk-* family on any "
            "endpoint of the same site, and look for the script path GUID below. "
            "If Kasada is present, there is no header tweak that resolves this - "
            "the check is a proof-of-work run in a real browser engine. Decide "
            "between using a real browser, requesting access, or stopping."
        ),
        "signals": [
            {"kind": "header", "name": "x-kpsdk-ct", "weight": 5},
            {"kind": "header", "name": "x-kpsdk-cd", "weight": 5},
            {"kind": "header", "name": "x-kpsdk-v", "weight": 4},
            {"kind": "header", "name": "x-kpsdk-r", "weight": 4},
            {"kind": "body", "contains": "149e9513-01fa-4fb0-aad4-566afd725d1b", "weight": 5},
            {"kind": "body", "contains": "kpsdk", "weight": 4},
            {"kind": "status", "codes": [429], "weight": 1},
        ],
    },
    {
        "name": "AWS WAF",
        "slug": "aws-waf",
        "product": "AWS WAF, with Bot Control / Challenge / CAPTCHA actions",
        "inspects": "Rule-set matching (IP sets, rate rules, managed rule "
                    "groups), plus a JS challenge and optional CAPTCHA for the "
                    "Challenge and CAPTCHA actions",
        "notes": "Statuses vary by action and by configuration. A plain Block "
                 "action returns 403 with a short body. The Challenge and CAPTCHA "
                 "actions serve an interstitial; 202 and 405 have both been "
                 "observed in the wild. The reliable markers are the awswaf.com "
                 "host in the body and the aws-waf-token cookie, not the status "
                 "code. Seeing CloudFront headers alone tells you nothing about "
                 "whether WAF is enabled.",
        "next_step": (
            "Most AWS WAF denials are a rule the site owner wrote, not adaptive "
            "bot scoring - often an IP reputation list, a rate-based rule, or a "
            "managed rule group reacting to your user agent. Try a plain honest "
            "user agent and a lower rate before assuming fingerprinting is "
            "involved. If a rate-based rule is the cause, backing off genuinely "
            "clears it after the evaluation window."
        ),
        "signals": [
            {"kind": "cookie", "name": "aws-waf-token", "weight": 5},
            {"kind": "header", "name": "x-amzn-waf-action", "weight": 5},
            {"kind": "body", "contains": "awswaf.com", "weight": 5},
            {"kind": "body", "contains": "aws-waf-token", "weight": 3},
            {"kind": "header", "name": "x-amz-cf-id", "weight": 1},
            {"kind": "header", "name": "server", "contains": "cloudfront", "weight": 1},
            {"kind": "status", "codes": [202, 403, 405], "weight": 1},
        ],
    },
    {
        "name": "Queue-it",
        "slug": "queue-it",
        "product": "Queue-it virtual waiting room",
        "inspects": "Nothing about your client. It is a FIFO queue keyed on an "
                    "issued token, used to cap concurrency during traffic peaks.",
        "notes": "Not an anti-bot product, and it is in this guide only because "
                 "it is misdiagnosed as one. You are not blocked; you are in line. "
                 "The redirect target carries the customer id, event id and your "
                 "original target URL as query parameters.",
        "next_step": (
            "Do not retry harder - retrying issues a new token and puts you back "
            "at the end of the line. Either wait for the queue to release you and "
            "keep the issued cookie, or schedule the work outside the traffic peak "
            "the waiting room exists to manage."
        ),
        "signals": [
            {"kind": "url", "contains": "queue-it.net", "weight": 5, "state": STATE_QUEUE},
            {"kind": "cookie", "name": "queueitaccepted", "mode": "prefix", "weight": 5,
             "state": STATE_QUEUE},
            {"kind": "cookie", "name": "queue-it", "mode": "prefix", "weight": 4,
             "state": STATE_QUEUE},
            {"kind": "body", "contains": "queue-it.net", "weight": 4, "state": STATE_QUEUE},
            {"kind": "body", "contains": "you are now in line", "weight": 3,
             "state": STATE_QUEUE},
            {"kind": "body", "contains": "waiting room", "weight": 2, "state": STATE_QUEUE},
        ],
    },
]

# Confidence thresholds, applied to the summed weight of matched signals.
CONFIDENCE_HIGH = 5
CONFIDENCE_MEDIUM = 3

_VALID_KINDS = frozenset({"header", "cookie", "body", "url", "status"})
_VALID_STATES = frozenset({STATE_BLOCK, STATE_CHALLENGE, STATE_QUEUE})

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

MAX_BODY_BYTES = 512 * 1024
_TRIM = 120


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class FetchError(Exception):
    """Raised by :func:`fetch` when no HTTP response could be obtained."""


def _trim(text, limit=_TRIM):
    # ASCII only: this string is printed to a terminal, and a Windows console
    # running a legacy code page raises UnicodeEncodeError on a real ellipsis.
    text = " ".join(str(text).split())
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _coerce_status(status):
    """Return ``status`` as an int, or ``None`` if it is not a usable code.

    A status read back out of a JSON log is often a string. Accept it rather
    than raising halfway through the comparisons.
    """
    if status is None or isinstance(status, bool):
        return None
    if isinstance(status, int):
        return status
    try:
        return int(str(status).strip())
    except (TypeError, ValueError):
        return None


def normalize_headers(headers):
    """Return ``{lowercase-name: [value, ...]}`` from any common header shape.

    Accepts a dict of str to str, a dict of str to list, a list of
    ``(name, value)`` pairs, or anything with an ``items()`` method such as
    :class:`http.client.HTTPMessage`. Duplicate headers are preserved, which
    matters for ``Set-Cookie``.
    """
    out = {}
    if not headers:
        return out
    if hasattr(headers, "items"):
        pairs = headers.items()
    else:
        pairs = headers
    for name, value in pairs:
        key = str(name).strip().lower()
        if isinstance(value, (list, tuple)):
            values = [str(v) for v in value]
        else:
            values = [str(value)]
        out.setdefault(key, []).extend(values)
    return out


def _cookie_names(header_map):
    names = []
    for raw in header_map.get("set-cookie", []):
        # A Set-Cookie value can legitimately contain commas (in Expires), so do
        # not split on commas. One header value, one cookie.
        first = raw.split(";", 1)[0]
        name = first.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


def _decode_body(body):
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray, memoryview)):
        data = bytes(body)[:MAX_BODY_BYTES]
        return data.decode("utf-8", errors="replace")
    return str(body)[:MAX_BODY_BYTES]


def _build_context(status, headers, body, url):
    status = _coerce_status(status)
    header_map = normalize_headers(headers)
    text = _decode_body(body)
    if url is None:
        urls = []
    elif isinstance(url, str):
        urls = [url]
    else:
        urls = [str(u) for u in url]
    return {
        "status": status,
        "headers": header_map,
        "cookies": _cookie_names(header_map),
        "body": text,
        "body_lower": text.lower(),
        "body_length": len(text),
        "urls": urls,
    }


def _match_signal(signal, ctx):
    """Return a human-readable description if the signal matches, else None."""
    kind = signal.get("kind")
    if kind == "header":
        values = ctx["headers"].get(signal["name"].lower())
        if not values:
            return None
        needle = signal.get("contains")
        if needle is not None:
            needle = needle.lower()
            for value in values:
                if needle in value.lower():
                    return "header {}: {}".format(signal["name"], _trim(value))
            return None
        return "header {}: {}".format(signal["name"], _trim(values[0]))
    if kind == "cookie":
        want = signal["name"].lower()
        prefix = signal.get("mode", "exact") == "prefix"
        for name in ctx["cookies"]:
            lowered = name.lower()
            hit = lowered.startswith(want) if prefix else lowered == want
            if hit:
                return "cookie {}".format(name)
        return None
    if kind == "body":
        needle = signal["contains"].lower()
        if needle in ctx["body_lower"]:
            return 'body contains "{}"'.format(_trim(signal["contains"]))
        return None
    if kind == "url":
        needle = signal["contains"].lower()
        for candidate in ctx["urls"]:
            if needle in candidate.lower():
                return 'url contains "{}"'.format(signal["contains"])
        return None
    if kind == "status":
        if ctx["status"] is not None and ctx["status"] in signal["codes"]:
            return "status {}".format(ctx["status"])
        return None
    raise ValueError("unknown signal kind: {!r}".format(kind))


def _confidence(score):
    if score >= CONFIDENCE_HIGH:
        return "high"
    if score >= CONFIDENCE_MEDIUM:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _resolve_state(states, status, vendor_found):
    for candidate in _STATE_PRECEDENCE:
        if candidate in states:
            return candidate
    if status is None:
        return STATE_UNKNOWN
    if 200 <= status < 400:
        return STATE_CLEAR
    if status >= 400:
        return STATE_BLOCK if vendor_found else STATE_UNKNOWN
    return STATE_UNKNOWN


def _hints(ctx, vendor_found, state, top=None):
    """Explanations that are *not* about a bot manager but look like one."""
    hints = []
    status = ctx["status"]
    headers = ctx["headers"]

    if top is not None and not vendor_found:
        hints.append(
            "Only weak markers matched ({} scored {}). That is corroboration, "
            "not an identification - read it as 'unidentified' until something "
            "stronger appears.".format(top["name"], top["score"])
        )

    if status == 429 and not vendor_found:
        retry_after = headers.get("retry-after")
        if retry_after:
            hints.append(
                "429 with Retry-After: {}. With no vendor markers this reads as "
                "ordinary rate limiting. Honour the header rather than rotating "
                "anything.".format(_trim(retry_after[0], 40))
            )
        else:
            hints.append(
                "429 with no Retry-After and no vendor markers. Ordinary rate "
                "limiting is the first explanation, but Kasada also answers with "
                "429 - check other endpoints of this site for x-kpsdk-* headers."
            )
    if status in (401, 407):
        hints.append(
            "{} is an authentication response, not bot detection. 401 is the "
            "origin asking you to log in; 407 is your proxy asking.".format(status)
        )
    if status == 451:
        hints.append("451 is a legal/geographic block. No client change resolves it.")
    if status == 402:
        hints.append("402 usually means a paywall or a metered API, not bot detection.")

    if status is not None and 300 <= status < 400:
        location = headers.get("location", [""])[0].lower()
        if any(token in location for token in ("login", "signin", "sign-in", "/auth")):
            hints.append(
                "Redirect to what looks like a login page. This is a login wall, "
                "not an anti-bot challenge."
            )

    content_type = headers.get("content-type", [""])[0].lower()
    if content_type and not any(
        token in content_type
        for token in ("html", "json", "xml", "text/plain", "javascript")
    ):
        hints.append(
            "Content-Type is {} - body markers were checked but are unlikely to "
            "apply to a non-text response.".format(_trim(content_type, 60))
        )

    if status is not None and status >= 400 and ctx["body_length"] == 0:
        hints.append(
            "Empty body on an error status. Log the response headers verbatim; "
            "they are the only evidence you will get."
        )

    if status == 200 and ctx["body_length"] < 1024:
        hints.append(
            "200 with a body under 1 KB. A short 200 is not proof of success - a "
            "transient empty page mistaken for 'end of results' is one of the "
            "cheapest ways to silently lose a large part of a dataset."
        )

    if state == STATE_CLEAR and vendor_found:
        hints.append(
            "A vendor was identified but this response looks like real content. "
            "The product is in front of the site; it is not blocking you now."
        )
    return hints


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def detect(status, headers=None, body=None, url=None):
    """Identify the anti-bot product behind a response. Pure function, no I/O.

    :param status: HTTP status code as an ``int``. A numeric string is accepted
        (log records often hold one); anything else is treated as ``None``.
    :param headers: dict, list of pairs, or ``HTTPMessage``. Case-insensitive.
    :param body: ``str`` or ``bytes``. Truncated to ``MAX_BODY_BYTES``.
    :param url: final URL, or a sequence of URLs (a redirect chain).
    :returns: a dict - see the README for the field list.
    """
    ctx = _build_context(status, headers, body, url)

    candidates = []
    states = set()
    for vendor in VENDORS:
        matched = []
        score = 0
        identifying = False
        vendor_states = set()
        for signal in vendor["signals"]:
            description = _match_signal(signal, ctx)
            if description is None:
                continue
            matched.append(description)
            score += int(signal.get("weight", 1))
            if signal["kind"] != "status":
                identifying = True
            signal_state = signal.get("state")
            if signal_state:
                vendor_states.add(signal_state)
        # A status code on its own identifies nobody - every vendor answers with
        # a 403 sooner or later.
        if identifying:
            # Only a vendor we actually believe in gets to set the state. A
            # single weak marker - an ordinary page containing the words
            # "waiting room", or an Apache 403 phrased the way Akamai phrases
            # its deny page - must not turn into "you are being blocked".
            if score >= CONFIDENCE_MEDIUM:
                states |= vendor_states
            candidates.append(
                {
                    "name": vendor["name"],
                    "slug": vendor["slug"],
                    "score": score,
                    "confidence": _confidence(score),
                    "signals": matched,
                    "next_step": vendor["next_step"],
                    "notes": vendor["notes"],
                }
            )

    candidates.sort(key=lambda item: (-item["score"], item["name"]))

    top = candidates[0] if candidates else None
    vendor_found = top is not None and top["confidence"] in ("high", "medium")
    state = _resolve_state(states, ctx["status"], vendor_found)

    title_match = _TITLE_RE.search(ctx["body"])
    title = _trim(title_match.group(1)) if title_match else None

    # Vendor-specific advice is only worth giving once a vendor has actually
    # been identified. A weight-2 match is not grounds for telling someone to go
    # and read Cloudflare error codes.
    if vendor_found:
        next_step = top["next_step"]
    elif top is None:
        next_step = (
            "No known vendor signature matched. Check the 'This is not an "
            "anti-bot problem' section of the README before changing your client: "
            "rate limits, geo blocks, login walls and malformed requests all look "
            "like this."
        )
    else:
        next_step = (
            "Nothing matched strongly enough to name a vendor. Check the 'This is "
            "not an anti-bot problem' section of the README before changing your "
            "client: rate limits, geo blocks, login walls and malformed requests "
            "all look like this."
        )

    return {
        "vendor": top["name"] if top else None,
        "slug": top["slug"] if top else None,
        "confidence": top["confidence"] if top else "none",
        "score": top["score"] if top else 0,
        "state": state,
        "signals": top["signals"] if top else [],
        "candidates": candidates,
        "next_step": next_step,
        "hints": _hints(ctx, vendor_found, state, top),
        "status": ctx["status"],
        "title": title,
        "body_length": ctx["body_length"],
    }


class _RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows redirects as usual, but remembers where it went."""

    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        return urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Stops at the first response so the redirect itself can be inspected."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


DEFAULT_USER_AGENT = "anti-bot-field-guide/{} (+diagnostic tool)".format(__version__)


def fetch(url, timeout=15.0, user_agent=DEFAULT_USER_AGENT, follow_redirects=True):
    """GET ``url`` with the standard library and return the raw pieces.

    :returns: ``(status, headers, body_bytes, urls)`` where ``urls`` is the
        final URL plus every redirect hop.
    :raises FetchError: if no HTTP response could be obtained at all.

    A 403 or 503 is a successful fetch for our purposes - the error response is
    exactly the thing we want to look at.
    """
    parsed = urllib.parse.urlsplit(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchError(
            "only http and https URLs are supported (got {!r})".format(parsed.scheme)
        )
    if not parsed.netloc:
        raise FetchError("no host in URL: {!r}".format(url))

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
        method="GET",
    )

    recorder = _RecordingRedirectHandler()
    handlers = [recorder] if follow_redirects else [_NoRedirectHandler()]
    opener = urllib.request.build_opener(*handlers)

    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except urllib.error.URLError as exc:
        raise FetchError("could not reach {}: {}".format(url, exc.reason)) from exc
    except socket.timeout as exc:  # pragma: no cover - platform dependent
        raise FetchError("timed out after {}s".format(timeout)) from exc
    except (OSError, ValueError) as exc:
        raise FetchError("could not reach {}: {}".format(url, exc)) from exc

    try:
        body = response.read(MAX_BODY_BYTES)
    except (OSError, ValueError) as exc:
        raise FetchError("connection dropped while reading body: {}".format(exc)) from exc
    finally:
        try:
            response.close()
        except Exception:  # pragma: no cover - defensive
            pass

    status = getattr(response, "status", None) or getattr(response, "code", None)
    final_url = getattr(response, "url", url) or url
    urls = [final_url] + recorder.chain
    return status, response.headers, body, urls


def load_record(source):
    """Read a saved response record from a JSON file, or from stdin for ``"-"``.

    The record is a JSON object with any of ``status``, ``headers``, ``body``
    and ``url`` - the same fields the README's "signals you should log" table
    asks you to keep. This is how you re-run :func:`detect` over a response you
    captured weeks ago, without touching the network.

    :raises ValueError: if the file is not a JSON object.
    :raises OSError: if the file cannot be read.
    """
    if source == "-":
        text = sys.stdin.read()
    else:
        with open(source, "r", encoding="utf-8") as handle:
            text = handle.read()
    record = json.loads(text)
    if not isinstance(record, dict):
        raise ValueError(
            "expected a JSON object with status/headers/body/url, got {}".format(
                type(record).__name__
            )
        )
    return record


def format_report(result, url=None, headers=None, verbose=False):
    """Render a :func:`detect` result as plain text."""
    lines = []
    if url:
        lines.append("URL        {}".format(url))
    lines.append("Status     {}".format(result["status"]))
    lines.append("Body       {} bytes".format(result["body_length"]))
    if result["title"]:
        lines.append("Title      {}".format(result["title"]))
    if result["vendor"]:
        lines.append(
            "Vendor     {}  (confidence: {}, score {})".format(
                result["vendor"], result["confidence"], result["score"]
            )
        )
    else:
        lines.append("Vendor     none matched")
    lines.append("State      {}".format(result["state"]))

    if result["signals"]:
        lines.append("")
        lines.append("Matched signals")
        for signal in result["signals"]:
            lines.append("  - {}".format(signal))

    others = result["candidates"][1:]
    if others:
        lines.append("")
        lines.append("Other candidates")
        for candidate in others:
            lines.append(
                "  - {} (score {}, {})".format(
                    candidate["name"], candidate["score"], candidate["confidence"]
                )
            )

    if result["hints"]:
        lines.append("")
        lines.append("Notes")
        for hint in result["hints"]:
            lines.append("  - {}".format(hint))

    lines.append("")
    lines.append("Next step")
    lines.append("  {}".format(result["next_step"]))

    if verbose and headers is not None:
        lines.append("")
        lines.append("Response headers")
        for name, values in sorted(normalize_headers(headers).items()):
            for value in values:
                lines.append("  {}: {}".format(name, _trim(value, 200)))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="detect.py",
        description="Identify which anti-bot / WAF product answered a request.",
        epilog="Exit codes: 0 ran successfully, 1 the request failed, "
               "2 bad usage. Use this on hosts you are permitted to query.",
    )
    parser.add_argument("url", nargs="?", help="http(s) URL to inspect")
    parser.add_argument(
        "--from-json",
        dest="from_json",
        metavar="FILE",
        help="read a saved response instead of making a request: a JSON object "
             "with status / headers / body / url. Use - for stdin.",
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0, help="seconds, default 15"
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="override the User-Agent. Comparing an honest UA against a "
             "browser UA is itself a useful diagnostic.",
    )
    parser.add_argument(
        "--no-redirect", action="store_true", help="do not follow redirects"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--verbose", action="store_true", help="also print every response header"
    )
    args = parser.parse_args(argv)

    # parser.error() exits 2, which is the documented "bad usage" code.
    if args.url and args.from_json:
        parser.error("give a URL or --from-json, not both")
    if not args.url and not args.from_json:
        parser.error("a URL or --from-json is required")

    if args.from_json:
        try:
            record = load_record(args.from_json)
        except (OSError, ValueError) as exc:
            print("could not read record: {}".format(exc), file=sys.stderr)
            return 1
        status = record.get("status")
        headers = record.get("headers")
        body = record.get("body")
        recorded_url = record.get("url")
        if isinstance(recorded_url, str):
            urls = [recorded_url]
        elif recorded_url:
            urls = [str(item) for item in recorded_url]
        else:
            urls = []
    else:
        try:
            status, headers, body, urls = fetch(
                args.url,
                timeout=args.timeout,
                user_agent=args.user_agent,
                follow_redirects=not args.no_redirect,
            )
        except FetchError as exc:
            print("fetch failed: {}".format(exc), file=sys.stderr)
            return 1

    result = detect(status, headers, body, url=urls)

    if args.json:
        payload = dict(result)
        payload["url"] = urls[0] if urls else args.url
        if args.verbose:
            payload["headers"] = normalize_headers(headers)
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            format_report(
                result, url=urls[0] if urls else args.url,
                headers=headers, verbose=args.verbose,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
