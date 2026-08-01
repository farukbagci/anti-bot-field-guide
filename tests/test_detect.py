"""Tests for detect.py.

No network access. Every fixture below is a hand-written approximation of a
response shape, using placeholder identifiers only. Nothing here was copied
from a live site and none of the ids, rays or tokens are real.

The tests that exercise ``fetch`` and ``main`` replace the URL opener with a
local stub, so nothing here can open a socket even by accident.
"""

import copy
import http.client
import io
import json
import os
import sys
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detect as detect_module  # noqa: E402
from detect import (  # noqa: E402
    STATE_BLOCK,
    STATE_CHALLENGE,
    STATE_CLEAR,
    STATE_QUEUE,
    STATE_UNKNOWN,
    VENDORS,
    FetchError,
    detect,
    fetch,
    format_report,
    load_record,
    main,
    normalize_headers,
)

HTML = "<html><head><title>Example Domain</title></head><body>{}</body></html>"


def _vendors_in(result):
    return {candidate["name"] for candidate in result["candidates"]}


# --------------------------------------------------------------------------
# Cloudflare
# --------------------------------------------------------------------------


def test_cloudflare_managed_challenge():
    headers = {
        "server": "cloudflare",
        "cf-ray": "0000000000000000-XXX",
        "cf-mitigated": "challenge",
        "content-type": "text/html; charset=UTF-8",
        "set-cookie": "__cf_bm=PLACEHOLDER; path=/; HttpOnly; Secure; SameSite=None",
    }
    body = (
        "<html><head><title>Just a moment...</title></head><body>"
        "<script src='/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1'></script>"
        "<script>window._cf_chl_opt={cvId:'3'};</script></body></html>"
    )
    result = detect(403, headers, body)
    assert result["vendor"] == "Cloudflare"
    assert result["confidence"] == "high"
    assert result["state"] == STATE_CHALLENGE
    assert result["title"] == "Just a moment..."


def test_cloudflare_legacy_js_challenge_503():
    headers = {"server": "cloudflare", "cf-ray": "0000000000000000-XXX"}
    body = HTML.format("<form id='challenge-form' action='/cdn-cgi/l/chk_jschl'></form>")
    result = detect(503, headers, body)
    assert result["vendor"] == "Cloudflare"
    assert result["state"] == STATE_CHALLENGE


def test_cloudflare_firewall_rule_1020_is_a_block_not_a_challenge():
    headers = {"server": "cloudflare", "cf-ray": "0000000000000000-XXX"}
    body = (
        "<html><head><title>Attention Required! | Cloudflare</title></head>"
        "<body><h1>Sorry, you have been blocked</h1>"
        "<span>Error 1020</span> Ray ID: 0000000000000000</body></html>"
    )
    result = detect(403, headers, body)
    assert result["vendor"] == "Cloudflare"
    assert result["state"] == STATE_BLOCK
    assert result["confidence"] == "high"


def test_cloudflare_rate_limit_1015_is_a_block():
    headers = {"server": "cloudflare", "cf-ray": "0000000000000000-XXX"}
    body = HTML.format("<h2>Error 1015</h2><p>You are being rate limited</p>")
    result = detect(429, headers, body)
    assert result["vendor"] == "Cloudflare"
    assert result["state"] == STATE_BLOCK


def test_cloudflare_in_front_but_response_is_clean():
    headers = {
        "server": "cloudflare",
        "cf-ray": "0000000000000000-XXX",
        "cf-cache-status": "HIT",
        "content-type": "text/html; charset=UTF-8",
    }
    body = HTML.format("<h1>Example Domain</h1>" + "content " * 300)
    result = detect(200, headers, body)
    assert result["vendor"] == "Cloudflare"
    assert result["state"] == STATE_CLEAR
    assert any("not blocking you now" in hint for hint in result["hints"])


# --------------------------------------------------------------------------
# DataDome
# --------------------------------------------------------------------------


def test_datadome_captcha_block_is_json_not_html():
    headers = {
        "content-type": "application/json",
        "x-datadome": "protected",
        "set-cookie": "datadome=PLACEHOLDER; Max-Age=31536000; Domain=.example.com; Path=/",
    }
    body = '{"url":"https://geo.captcha-delivery.com/captcha/?initialCid=PLACEHOLDER"}'
    result = detect(403, headers, body)
    assert result["vendor"] == "DataDome"
    assert result["confidence"] == "high"
    assert result["state"] == STATE_CHALLENGE


def test_datadome_cookie_on_a_normal_page():
    headers = {
        "content-type": "text/html",
        "set-cookie": "datadome=PLACEHOLDER; Path=/; Secure; SameSite=Lax",
    }
    result = detect(200, headers, HTML.format("real content " * 200))
    assert result["vendor"] == "DataDome"
    assert result["state"] == STATE_CLEAR


# --------------------------------------------------------------------------
# PerimeterX / HUMAN
# --------------------------------------------------------------------------


def test_perimeterx_json_block_payload():
    headers = {"content-type": "application/json"}
    body = (
        '{"appId":"PXexample0","jsClientSrc":"/PXexample0/init.js",'
        '"firstPartyEnabled":true,"vid":"00000000-0000-0000-0000-000000000000",'
        '"uuid":"00000000-0000-0000-0000-000000000000","hostUrl":"/PXexample0/xhr"}'
    )
    result = detect(403, headers, body)
    assert result["vendor"] == "PerimeterX (HUMAN)"
    assert result["state"] == STATE_BLOCK


def test_perimeterx_block_page_html():
    headers = {
        "content-type": "text/html",
        "set-cookie": "_pxhd=PLACEHOLDER; Expires=Tue, 01 Jan 2030 00:00:00 GMT; Path=/",
    }
    body = HTML.format(
        "<h1>Access to this page has been denied</h1>"
        "<script src='https://captcha.px-cloud.net/PXexample0/captcha.js'></script>"
    )
    result = detect(403, headers, body)
    assert result["vendor"] == "PerimeterX (HUMAN)"
    assert result["confidence"] == "high"
    assert result["state"] == STATE_BLOCK


def test_perimeterx_cookies_on_a_clean_response():
    headers = [
        ("content-type", "text/html"),
        ("set-cookie", "_px3=PLACEHOLDER; Path=/; Secure"),
        ("set-cookie", "_pxvid=00000000-0000-0000-0000-000000000000; Path=/"),
        ("set-cookie", "pxcts=00000000-0000-0000-0000-000000000000; Path=/"),
    ]
    result = detect(200, headers, HTML.format("catalogue " * 300))
    assert result["vendor"] == "PerimeterX (HUMAN)"
    assert result["state"] == STATE_CLEAR


# --------------------------------------------------------------------------
# Akamai
# --------------------------------------------------------------------------


def test_akamai_cookies_on_a_clean_response():
    headers = [
        ("content-type", "text/html"),
        ("set-cookie", "_abck=PLACEHOLDER~-1~PLACEHOLDER~-1~-1~-1; Path=/; Secure"),
        ("set-cookie", "bm_sz=PLACEHOLDER; Domain=.example.com; Path=/"),
        ("set-cookie", "ak_bmsc=PLACEHOLDER; Domain=.example.com; Path=/"),
    ]
    result = detect(200, headers, HTML.format("search results " * 200))
    assert result["vendor"] == "Akamai Bot Manager"
    assert result["confidence"] == "high"
    assert result["state"] == STATE_CLEAR


def test_akamai_access_denied_reference_page():
    headers = {"server": "AkamaiGHost", "content-type": "text/html", "mime-version": "1.0"}
    body = (
        "<html><head><title>Access Denied</title></head><body>"
        "<h1>Access Denied</h1>You don't have permission to access "
        "&quot;/search&quot; on this server.<p>Reference #18.00000000.0000000000."
        "0000000</p></body></html>"
    )
    result = detect(403, headers, body)
    assert result["vendor"] == "Akamai Bot Manager"
    assert result["state"] == STATE_BLOCK


# --------------------------------------------------------------------------
# Imperva / Incapsula
# --------------------------------------------------------------------------


def test_imperva_incident_id_block():
    headers = {
        "content-type": "text/html",
        "x-iinfo": "0-00000000-00000000 NNNN RT(0000000000 0) q(0 0 0 0) r(0 0)",
        "x-cdn": "Incapsula",
    }
    body = (
        "<html><head><title>Access denied</title></head><body>"
        "Request unsuccessful. Incapsula incident ID: "
        "0000000000000000000-000000000000000000</body></html>"
    )
    result = detect(403, headers, body)
    assert result["vendor"] == "Imperva (Incapsula)"
    assert result["confidence"] == "high"
    assert result["state"] == STATE_BLOCK


def test_imperva_advanced_bot_protection_interstitial():
    headers = [
        ("content-type", "text/html"),
        ("set-cookie", "reese84=PLACEHOLDER; Path=/; Secure; HttpOnly"),
        ("set-cookie", "visid_incap_000000=PLACEHOLDER; Path=/; Domain=.example.com"),
        ("set-cookie", "incap_ses_000_000000=PLACEHOLDER; Path=/"),
    ]
    body = HTML.format("<script src='/_Incapsula_Resource?SWJIYLWA=0000'></script>")
    result = detect(200, headers, body)
    assert result["vendor"] == "Imperva (Incapsula)"
    assert result["confidence"] == "high"


def test_imperva_nlbi_cookie_prefix_matches():
    headers = {"set-cookie": "nlbi_000000=PLACEHOLDER; path=/; Domain=.example.com"}
    result = detect(200, headers, HTML.format("page"))
    assert result["vendor"] == "Imperva (Incapsula)"


# --------------------------------------------------------------------------
# Kasada
# --------------------------------------------------------------------------


def test_kasada_429_is_not_plain_rate_limiting():
    headers = {"x-kpsdk-ct": "PLACEHOLDER", "content-length": "0"}
    result = detect(429, headers, "")
    assert result["vendor"] == "Kasada"
    assert result["confidence"] == "high"
    assert result["state"] == STATE_BLOCK
    # The rate-limit hint must not fire when a vendor was identified.
    assert not any("ordinary rate limiting" in hint for hint in result["hints"])


def test_kasada_script_path_guid_in_body():
    headers = {"content-type": "text/html"}
    body = HTML.format(
        "<script src='/149e9513-01fa-4fb0-aad4-566afd725d1b/"
        "2d206a39-8ed7-437e-a3be-862e0f06eee3/p.js'></script>"
    )
    result = detect(200, headers, body)
    assert result["vendor"] == "Kasada"


# --------------------------------------------------------------------------
# AWS WAF
# --------------------------------------------------------------------------


def test_aws_waf_block():
    headers = {
        "server": "CloudFront",
        "x-amzn-waf-action": "block",
        "x-amz-cf-id": "PLACEHOLDER",
        "content-type": "text/html",
    }
    result = detect(403, headers, HTML.format("<h1>403 Forbidden</h1>"))
    assert result["vendor"] == "AWS WAF"
    assert result["state"] == STATE_BLOCK


def test_aws_waf_challenge_interstitial():
    headers = {
        "content-type": "text/html",
        "set-cookie": "aws-waf-token=00000000-0000-0000-0000-000000000000:PLACEHOLDER; Path=/",
    }
    body = HTML.format(
        "<script src='https://00000000.eu-west-1.captcha.awswaf.com/"
        "00000000/jsapi.js'></script>"
    )
    result = detect(202, headers, body)
    assert result["vendor"] == "AWS WAF"
    assert result["confidence"] == "high"


def test_cloudfront_headers_alone_are_only_weak_evidence():
    headers = {"server": "CloudFront", "x-amz-cf-id": "PLACEHOLDER"}
    result = detect(200, headers, HTML.format("content " * 300))
    assert result["vendor"] == "AWS WAF"
    assert result["confidence"] == "low"


# --------------------------------------------------------------------------
# Queue-it
# --------------------------------------------------------------------------


def test_queue_it_redirect_is_detected_from_the_url_chain():
    headers = {
        "location": "https://example.queue-it.net/?c=example&e=sale&t=https%3A%2F%2Fexample.com%2F"
    }
    result = detect(
        302,
        headers,
        "",
        url=["https://example.com/", "https://example.queue-it.net/?c=example&e=sale"],
    )
    assert result["vendor"] == "Queue-it"
    assert result["state"] == STATE_QUEUE


def test_queue_it_waiting_room_page():
    headers = {
        "content-type": "text/html",
        "set-cookie": "QueueITAccepted-SDFrts345E-V3_example=PLACEHOLDER; Path=/",
    }
    body = HTML.format("<h1>You are now in line</h1><p>waiting room</p>")
    result = detect(200, headers, body)
    assert result["vendor"] == "Queue-it"
    assert result["state"] == STATE_QUEUE


# --------------------------------------------------------------------------
# Clean and ambiguous responses
# --------------------------------------------------------------------------


def test_plain_nginx_200_matches_nothing():
    headers = {"server": "nginx", "content-type": "text/html; charset=utf-8"}
    result = detect(200, headers, HTML.format("hello " * 300))
    assert result["vendor"] is None
    assert result["confidence"] == "none"
    assert result["state"] == STATE_CLEAR
    assert result["candidates"] == []


def test_plain_404_matches_nothing():
    headers = {"server": "nginx", "content-type": "text/html"}
    result = detect(404, headers, HTML.format("<h1>Not Found</h1>"))
    assert result["vendor"] is None
    assert result["state"] == STATE_UNKNOWN


def test_plain_rate_limit_is_reported_as_not_anti_bot():
    headers = {"server": "nginx", "retry-after": "60", "content-type": "application/json"}
    result = detect(429, headers, '{"error":"too many requests"}')
    assert result["vendor"] is None
    assert any("ordinary rate limiting" in hint for hint in result["hints"])


def test_bare_403_with_no_markers_stays_honest():
    headers = {"server": "nginx"}
    result = detect(403, headers, "")
    assert result["vendor"] is None
    assert result["state"] == STATE_UNKNOWN
    assert "not an anti-bot problem" in result["next_step"].lower()


def test_login_wall_redirect_hint():
    headers = {"location": "https://example.com/login?next=%2Faccount"}
    result = detect(302, headers, "")
    assert any("login wall" in hint for hint in result["hints"])


def test_auth_status_codes_are_flagged_as_not_anti_bot():
    assert any("authentication" in h for h in detect(401, {}, "")["hints"])
    assert any("proxy" in h for h in detect(407, {}, "")["hints"])


def test_legal_block_hint():
    assert any("legal" in hint for hint in detect(451, {}, "")["hints"])


def test_short_200_body_is_flagged():
    result = detect(200, {"server": "nginx"}, "<html></html>")
    assert any("silently lose" in hint for hint in result["hints"])


def test_non_text_content_type_is_flagged():
    result = detect(200, {"content-type": "application/pdf"}, b"%PDF-1.7\n%\xe2\xe3\xcf\xd3")
    assert any("Content-Type" in hint for hint in result["hints"])


def test_two_vendors_can_appear_together():
    headers = [
        ("server", "cloudflare"),
        ("cf-ray", "0000000000000000-XXX"),
        ("set-cookie", "datadome=PLACEHOLDER; Path=/"),
    ]
    result = detect(403, headers, '{"url":"https://geo.captcha-delivery.com/captcha/"}')
    assert {"Cloudflare", "DataDome"} <= _vendors_in(result)
    assert result["vendor"] == "DataDome"


def test_candidates_are_sorted_by_descending_score():
    headers = {
        "server": "cloudflare",
        "cf-ray": "0000000000000000-XXX",
        "x-amz-cf-id": "PLACEHOLDER",
    }
    result = detect(403, headers, "")
    scores = [candidate["score"] for candidate in result["candidates"]]
    assert scores == sorted(scores, reverse=True)


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------


def test_header_names_are_case_insensitive():
    upper = detect(403, {"CF-RAY": "0000000000000000-XXX", "Server": "cloudflare"}, "")
    lower = detect(403, {"cf-ray": "0000000000000000-XXX", "server": "cloudflare"}, "")
    assert upper["vendor"] == lower["vendor"] == "Cloudflare"
    assert upper["score"] == lower["score"]


def test_bytes_body_is_accepted():
    body = HTML.format("Just a moment").encode("utf-8")
    assert detect(403, {"cf-ray": "0000000000000000-XXX"}, body)["vendor"] == "Cloudflare"


def test_undecodable_bytes_do_not_raise():
    result = detect(403, {"server": "nginx"}, b"\xff\xfe\x00\x01binary")
    assert result["vendor"] is None


def test_none_body_and_none_headers_are_accepted():
    result = detect(None, None, None)
    assert result["vendor"] is None
    assert result["state"] == STATE_UNKNOWN
    assert result["body_length"] == 0


def test_duplicate_set_cookie_values_are_all_read():
    headers = [
        ("set-cookie", "session=PLACEHOLDER; Path=/"),
        ("set-cookie", "_abck=PLACEHOLDER; Path=/"),
        ("set-cookie", "bm_sz=PLACEHOLDER; Path=/"),
    ]
    result = detect(200, headers, "")
    assert result["vendor"] == "Akamai Bot Manager"


def test_set_cookie_with_comma_in_expires_is_not_split():
    headers = {
        "set-cookie": "_abck=PLACEHOLDER; expires=Thu, 01 Jan 2030 00:00:00 GMT; path=/"
    }
    result = detect(200, headers, "")
    assert "cookie _abck" in result["signals"]


def test_normalize_headers_accepts_dict_list_and_pairs():
    assert normalize_headers({"A": "1"}) == {"a": ["1"]}
    assert normalize_headers([("A", "1"), ("a", "2")]) == {"a": ["1", "2"]}
    assert normalize_headers({"A": ["1", "2"]}) == {"a": ["1", "2"]}
    assert normalize_headers(None) == {}


def test_body_is_truncated_and_does_not_blow_up():
    result = detect(200, {"server": "nginx"}, "x" * (2 * 1024 * 1024))
    assert result["body_length"] <= 512 * 1024


# --------------------------------------------------------------------------
# Signature table integrity - this is what keeps contributions honest
# --------------------------------------------------------------------------

_VALID_KINDS = {"header", "cookie", "body", "url", "status"}
_VALID_STATES = {STATE_BLOCK, STATE_CHALLENGE, STATE_QUEUE}


@pytest.mark.parametrize("vendor", VENDORS, ids=lambda v: v["slug"])
def test_vendor_entry_is_well_formed(vendor):
    for key in ("name", "slug", "product", "inspects", "notes", "next_step", "signals"):
        assert key in vendor, "{} is missing {!r}".format(vendor.get("name"), key)
        assert isinstance(vendor[key], (str, list))
    assert vendor["signals"], "a vendor with no signals can never match"

    for signal in vendor["signals"]:
        assert signal["kind"] in _VALID_KINDS
        weight = signal.get("weight", 1)
        assert isinstance(weight, int) and 1 <= weight <= 5
        if "state" in signal:
            assert signal["state"] in _VALID_STATES
        if signal["kind"] == "header":
            assert signal["name"]
        elif signal["kind"] == "cookie":
            assert signal.get("mode", "exact") in ("exact", "prefix")
        elif signal["kind"] in ("body", "url"):
            assert signal["contains"]
        elif signal["kind"] == "status":
            assert all(isinstance(code, int) for code in signal["codes"])


def test_vendor_names_and_slugs_are_unique():
    names = [vendor["name"] for vendor in VENDORS]
    slugs = [vendor["slug"] for vendor in VENDORS]
    assert len(set(names)) == len(names)
    assert len(set(slugs)) == len(slugs)


def test_no_vendor_reaches_high_confidence_on_a_status_code_alone():
    for code in (202, 403, 405, 429, 503):
        result = detect(code, {}, "")
        assert result["confidence"] in ("none", "low"), code


def test_unknown_signal_kind_raises():
    from detect import _match_signal, _build_context

    ctx = _build_context(200, {}, "", None)
    with pytest.raises(ValueError):
        _match_signal({"kind": "telepathy"}, ctx)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def test_format_report_contains_the_essentials():
    headers = {"server": "cloudflare", "cf-ray": "0000000000000000-XXX"}
    body = HTML.format("Just a moment")
    text = format_report(detect(403, headers, body), url="https://example.com/")
    assert "Cloudflare" in text
    assert "https://example.com/" in text
    assert "Next step" in text


def test_format_report_verbose_lists_headers():
    headers = {"server": "cloudflare", "cf-ray": "0000000000000000-XXX"}
    result = detect(403, headers, "")
    text = format_report(result, url="https://example.com/", headers=headers, verbose=True)
    assert "Response headers" in text
    assert "cf-ray" in text


def test_format_report_handles_a_clean_unknown_response():
    text = format_report(detect(200, {"server": "nginx"}, HTML.format("hi " * 300)))
    assert "none matched" in text


def test_format_report_lists_the_other_candidates():
    headers = {
        "server": "cloudflare",
        "cf-ray": "0000000000000000-XXX",
        "set-cookie": "datadome=PLACEHOLDER; Path=/",
    }
    body = '{"url":"https://geo.captcha-delivery.com/captcha/"}'
    text = format_report(detect(403, headers, body))
    assert "Other candidates" in text
    assert "Cloudflare" in text


def test_report_output_is_ascii_so_a_legacy_console_can_print_it():
    # A long header value gets trimmed; the trim marker must not be U+2026,
    # which a Windows console on a legacy code page cannot encode.
    headers = {"server": "cloudflare", "cf-ray": "0000000000000000-XXX",
               "x-long": "value " * 200}
    text = format_report(detect(403, headers, ""), headers=headers, verbose=True)
    assert "..." in text
    text.encode("ascii")  # raises if a non-ASCII character crept in


# --------------------------------------------------------------------------
# False positives - a weak marker must never be reported as a verdict
# --------------------------------------------------------------------------


def test_the_words_waiting_room_on_a_normal_page_are_not_a_queue():
    body = HTML.format("Our waiting room opens at 08:00. " * 40)
    result = detect(200, {"server": "nginx", "content-type": "text/html"}, body)
    assert result["state"] == STATE_CLEAR
    assert result["confidence"] == "low"


def test_an_apache_style_403_wording_is_not_reported_as_an_akamai_block():
    # Stock Apache uses the same sentence as an Akamai deny page. On its own it
    # is worth 2, and 2 must not be enough to call a block.
    body = HTML.format("You don't have permission to access /private/ " * 30)
    result = detect(200, {"server": "nginx"}, body)
    assert result["state"] == STATE_CLEAR
    assert result["confidence"] == "low"


def test_prose_containing_just_a_moment_is_not_a_cloudflare_challenge():
    body = HTML.format("Please wait just a moment while we confirm your order. " * 20)
    result = detect(200, {"server": "nginx"}, body)
    assert result["vendor"] is None
    assert result["state"] == STATE_CLEAR


def test_the_real_interstitial_title_still_matches():
    body = "<html><head><title>Just a moment...</title></head><body></body></html>"
    result = detect(403, {"cf-ray": "0000000000000000-XXX"}, body)
    assert result["vendor"] == "Cloudflare"
    assert result["state"] == STATE_CHALLENGE


def test_a_weak_match_is_still_listed_as_a_candidate():
    body = HTML.format("Our waiting room opens at 08:00. " * 40)
    result = detect(200, {"server": "nginx"}, body)
    assert "Queue-it" in _vendors_in(result)


def test_a_weak_match_is_labelled_as_weak():
    result = detect(200, {"server": "CloudFront", "x-amz-cf-id": "PLACEHOLDER"},
                    HTML.format("content " * 300))
    assert result["confidence"] == "low"
    assert any("Only weak markers matched" in hint for hint in result["hints"])


def test_a_weak_match_does_not_hand_out_vendor_specific_advice():
    weak = detect(200, {"server": "CloudFront", "x-amz-cf-id": "PLACEHOLDER"},
                  HTML.format("content " * 300))
    strong = detect(403, {"x-amzn-waf-action": "block"}, HTML.format("Forbidden"))
    assert "not an anti-bot problem" in weak["next_step"].lower()
    assert weak["next_step"] != strong["next_step"]
    assert "AWS WAF" in strong["candidates"][0]["name"]


# --------------------------------------------------------------------------
# Input handling, continued
# --------------------------------------------------------------------------


def test_status_read_back_from_a_json_log_as_a_string_is_accepted():
    result = detect("403", {"cf-ray": "0000000000000000-XXX"}, "")
    assert result["status"] == 403
    assert result["vendor"] == "Cloudflare"
    assert "status 403" in result["signals"]


def test_an_unusable_status_is_treated_as_unknown_rather_than_raising():
    result = detect("n/a", {"server": "nginx"}, "")
    assert result["status"] is None
    assert result["state"] == STATE_UNKNOWN


def test_httpmessage_headers_are_accepted():
    message = http.client.HTTPMessage()
    message["Server"] = "cloudflare"
    message["CF-RAY"] = "0000000000000000-XXX"
    message.add_header("Set-Cookie", "__cf_bm=PLACEHOLDER; Path=/")
    result = detect(403, message, "")
    assert result["vendor"] == "Cloudflare"
    assert "cookie __cf_bm" in result["signals"]


def test_url_accepts_a_bare_string_as_well_as_a_chain():
    single = detect(302, {}, "", url="https://example.queue-it.net/?c=example")
    chain = detect(302, {}, "", url=["https://example.queue-it.net/?c=example"])
    assert single["vendor"] == chain["vendor"] == "Queue-it"


def test_detect_does_not_mutate_the_signature_table():
    before = copy.deepcopy(VENDORS)
    detect(403, {"cf-ray": "0000000000000000-XXX"}, "Just a moment...")
    assert VENDORS == before


def test_every_vendor_is_identifiable_without_its_status_signal():
    for vendor in VENDORS:
        kinds = {signal["kind"] for signal in vendor["signals"]}
        assert kinds - {"status"}, vendor["name"]


def test_every_marker_is_ascii():
    # Markers are echoed to a terminal and compared against a decoded body.
    for vendor in VENDORS:
        for signal in vendor["signals"]:
            for key in ("name", "contains"):
                value = signal.get(key)
                if value is not None:
                    value.encode("ascii")


# --------------------------------------------------------------------------
# fetch() - transport handling, with the opener stubbed out. No sockets.
# --------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", url="https://example.com/"):
        self.status = status
        self.headers = headers or {}
        self.url = url
        self._body = body
        self.closed = False

    def read(self, amount=None):
        return self._body[:amount] if amount else self._body

    def close(self):
        self.closed = True


class _FakeOpener:
    def __init__(self, result):
        self._result = result
        self.calls = []

    def open(self, request, timeout=None):
        self.calls.append((request, timeout))
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _stub_opener(monkeypatch, result):
    opener = _FakeOpener(result)
    monkeypatch.setattr(
        detect_module.urllib.request, "build_opener", lambda *handlers: opener
    )
    return opener


def test_fetch_rejects_a_non_http_scheme_before_opening_anything(monkeypatch):
    monkeypatch.setattr(
        detect_module.urllib.request,
        "build_opener",
        lambda *a: pytest.fail("fetch must validate the URL before opening it"),
    )
    with pytest.raises(FetchError) as excinfo:
        fetch("ftp://example.com/file")
    assert "http and https" in str(excinfo.value)


def test_fetch_rejects_a_url_with_no_host(monkeypatch):
    monkeypatch.setattr(
        detect_module.urllib.request,
        "build_opener",
        lambda *a: pytest.fail("fetch must validate the URL before opening it"),
    )
    with pytest.raises(FetchError):
        fetch("https:///nothing")


def test_fetch_adds_a_scheme_when_none_was_given(monkeypatch):
    opener = _stub_opener(monkeypatch, _FakeResponse())
    fetch("example.com")
    request = opener.calls[0][0]
    assert request.full_url.startswith("https://")


def test_fetch_returns_status_headers_body_and_the_redirect_chain(monkeypatch):
    response = _FakeResponse(
        status=403,
        headers={"cf-ray": "0000000000000000-XXX"},
        body=b"<html>blocked</html>",
        url="https://example.com/final",
    )
    _stub_opener(monkeypatch, response)
    status, headers, body, urls = fetch("https://example.com/", timeout=1.0)
    assert status == 403
    assert body == b"<html>blocked</html>"
    assert urls == ["https://example.com/final"]
    assert response.closed
    assert detect(status, headers, body, url=urls)["vendor"] == "Cloudflare"


def test_fetch_passes_the_timeout_and_user_agent_through(monkeypatch):
    opener = _stub_opener(monkeypatch, _FakeResponse())
    fetch("https://example.com/", timeout=2.5, user_agent="probe/1.0")
    request, timeout = opener.calls[0]
    assert timeout == 2.5
    assert request.get_header("User-agent") == "probe/1.0"


def test_fetch_treats_an_http_error_response_as_a_successful_fetch(monkeypatch):
    error = urllib.error.HTTPError(
        "https://example.com/", 403, "Forbidden",
        http.client.HTTPMessage(), io.BytesIO(b"denied"),
    )
    _stub_opener(monkeypatch, error)
    status, _headers, body, _urls = fetch("https://example.com/")
    assert status == 403
    assert body == b"denied"


def test_fetch_wraps_a_transport_failure_in_fetch_error(monkeypatch):
    _stub_opener(monkeypatch, urllib.error.URLError("name or service not known"))
    with pytest.raises(FetchError) as excinfo:
        fetch("https://example.invalid/")
    assert "could not reach" in str(excinfo.value)


def test_fetch_reports_a_body_read_that_dies_midway(monkeypatch):
    class _Broken(_FakeResponse):
        def read(self, amount=None):
            raise OSError("connection reset")

    _stub_opener(monkeypatch, _Broken())
    with pytest.raises(FetchError) as excinfo:
        fetch("https://example.com/")
    assert "connection dropped" in str(excinfo.value)


# --------------------------------------------------------------------------
# load_record() and the CLI. Every case below is offline.
# --------------------------------------------------------------------------

RECORD = {
    "status": 403,
    "url": "https://example.com/search",
    "headers": {
        "server": "cloudflare",
        "cf-ray": "0000000000000000-XXX",
        "cf-mitigated": "challenge",
        "set-cookie": ["__cf_bm=PLACEHOLDER; Path=/"],
    },
    "body": "<html><head><title>Just a moment...</title></head><body>"
            "<script src='/cdn-cgi/challenge-platform/h/b/x'></script></body></html>",
}


def _write_record(tmp_path, record, name="record.json"):
    path = tmp_path / name
    path.write_text(json.dumps(record), encoding="utf-8")
    return str(path)


def test_load_record_reads_a_json_object(tmp_path):
    assert load_record(_write_record(tmp_path, RECORD))["status"] == 403


def test_load_record_rejects_a_json_array(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError):
        load_record(str(path))


def test_load_record_reads_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(RECORD)))
    assert load_record("-")["url"] == "https://example.com/search"


def test_cli_replays_a_saved_response_without_a_network_call(tmp_path, capsys):
    assert main(["--from-json", _write_record(tmp_path, RECORD)]) == 0
    out = capsys.readouterr().out
    assert "Cloudflare" in out
    assert "State      challenge" in out
    assert "https://example.com/search" in out


def test_cli_json_output_is_parseable(tmp_path, capsys):
    assert main(["--from-json", _write_record(tmp_path, RECORD), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["vendor"] == "Cloudflare"
    assert payload["state"] == "challenge"
    assert payload["url"] == "https://example.com/search"
    assert "headers" not in payload


def test_cli_verbose_json_includes_the_headers(tmp_path, capsys):
    argv = ["--from-json", _write_record(tmp_path, RECORD), "--json", "--verbose"]
    assert main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["headers"]["cf-ray"] == ["0000000000000000-XXX"]


def test_cli_handles_a_record_with_only_a_status(tmp_path, capsys):
    assert main(["--from-json", _write_record(tmp_path, {"status": 404})]) == 0
    assert "none matched" in capsys.readouterr().out


def test_cli_returns_1_for_a_missing_record(tmp_path, capsys):
    assert main(["--from-json", str(tmp_path / "absent.json")]) == 1
    assert "could not read record" in capsys.readouterr().err


def test_cli_returns_1_for_a_malformed_record(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert main(["--from-json", str(path)]) == 1
    assert "could not read record" in capsys.readouterr().err


def test_cli_requires_a_url_or_a_record():
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_cli_refuses_a_url_and_a_record_together(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        main(["https://example.com", "--from-json", _write_record(tmp_path, RECORD)])
    assert excinfo.value.code == 2


def test_cli_help_exits_zero():
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0


def test_cli_fetches_when_given_a_url(monkeypatch, capsys):
    calls = {}

    def fake_fetch(url, timeout, user_agent, follow_redirects):
        calls.update(
            url=url, timeout=timeout, user_agent=user_agent,
            follow_redirects=follow_redirects,
        )
        return 429, {"x-kpsdk-ct": "PLACEHOLDER"}, b"", ["https://example.com/"]

    monkeypatch.setattr(detect_module, "fetch", fake_fetch)
    assert main(["https://example.com/", "--timeout", "3", "--no-redirect"]) == 0
    assert calls == {
        "url": "https://example.com/",
        "timeout": 3.0,
        "user_agent": detect_module.DEFAULT_USER_AGENT,
        "follow_redirects": False,
    }
    assert "Kasada" in capsys.readouterr().out


def test_cli_returns_1_when_the_request_fails(monkeypatch, capsys):
    def fake_fetch(url, timeout, user_agent, follow_redirects):
        raise FetchError("could not reach https://example.invalid/")

    monkeypatch.setattr(detect_module, "fetch", fake_fetch)
    assert main(["https://example.invalid/"]) == 1
    assert "fetch failed" in capsys.readouterr().err
