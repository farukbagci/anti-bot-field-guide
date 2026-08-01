# Signature reference

The raw data behind [`detect.py`](detect.py), in a form you can read without running anything.

Everything here is observable from the outside: response headers, cookie *names*, status codes and
markers in the response body. No sample contains a real token, ray id, incident id or session value.

> Signatures drift. Vendors rename cookies, move scripts to first-party paths and change status
> codes per customer configuration. Treat a row as "what to look for first", not as a contract. The
> weights in `detect.py` encode how much each item is worth on its own.

---

## Weighting

| Weight | Meaning |
|---|---|
| 5 | Unique to this vendor, present on any response from it |
| 4 | Unique to this vendor, but only on a block or challenge response |
| 3 | Strongly associated, small chance of collision |
| 2 | Consistent with this vendor, also seen elsewhere |
| 1 | Weak corroboration only (status codes, generic CDN headers) |

A `status` signal never identifies a vendor by itself. Every product in this list answers with a
`403` at some point, so the matcher requires at least one header, cookie, body or URL match before
it will name anybody.

Confidence from the summed weight: **high** at 5 or more, **medium** at 3–4, **low** at 1–2.

A `state` of block, challenge or queue is only taken from a vendor whose summed weight reached 3.
A single weak marker — an ordinary page containing the words "waiting room", or a stock Apache 403
worded the way an Akamai deny page is worded — is reported as a low-confidence candidate and
nothing more. The tool should not tell you that you are blocked on the strength of one common
English phrase.

The markers are matched case-insensitively, so the tables below are written the way you would read
them on the page. They are matched as plain substrings: `Just a moment...` carries its trailing
dots deliberately, because the words on their own appear in ordinary page copy.

---

## Cloudflare

| Kind | Signal | Weight | Only on block/challenge |
|---|---|---|---|
| header | `cf-ray` | 5 | |
| header | `cf-mitigated` | 5 | challenge |
| header | `cf-cache-status` | 2 | |
| header | `server: cloudflare` | 2 | |
| cookie | `__cf_bm` | 4 | |
| cookie | `cf_clearance` | 4 | |
| cookie | `__cflb` | 2 | |
| body | `cdn-cgi/challenge-platform` | 5 | challenge |
| body | `window._cf_chl_opt` | 5 | challenge |
| body | `Just a moment...` | 4 | challenge |
| body | `/cdn-cgi/l/chk_jschl` | 4 | challenge (legacy) |
| body | `challenges.cloudflare.com/turnstile` | 4 | challenge |
| body | `Attention Required! \| Cloudflare` | 5 | block |
| body | `Sorry, you have been blocked` | 4 | block |
| body | `Error 1020` / `Error 1015` / `Error 1010` | 4 | block |
| status | 403, 429, 503 | 1 | |

The numeric error code in the body is the most useful thing on a Cloudflare block page:

| Code | Meaning |
|---|---|
| 1010 | Access denied based on the browser's signature |
| 1015 | Rate limited by a rate-limiting rule |
| 1020 | Access denied by a firewall (WAF) rule |

`__cfduid` was retired in 2021 and replaced by `__cf_bm`. If you see it in an old write-up, that
write-up is stale.

---

## DataDome

| Kind | Signal | Weight | Only on block/challenge |
|---|---|---|---|
| cookie | `datadome` | 5 | |
| header | `x-datadome` | 4 | |
| body | `captcha-delivery.com` | 5 | challenge |
| body | `datadome` | 2 | |
| status | 403 | 1 | |

The block response is usually **JSON, not HTML**, shaped roughly like:

```json
{"url": "https://geo.captcha-delivery.com/captcha/?initialCid=...&cid=...&t=bv"}
```

The status code for a block is configurable by the site operator, so key on the cookie and the
captcha host rather than on the status. `x-datadome` is present on many but not all deployments.

---

## PerimeterX / HUMAN

| Kind | Signal | Weight | Only on block/challenge |
|---|---|---|---|
| cookie | `_px3` | 5 | |
| cookie | `_pxvid` | 4 | |
| cookie | `pxcts` | 4 | |
| cookie | `_pxhd` | 4 | |
| cookie | `_pxCaptcha` | 4 | challenge |
| body | `_pxAppId` | 5 | |
| body | `"appId":"PX` | 5 | block |
| body | `jsClientSrc` | 5 | |
| body | `px-cloud.net` | 5 | |
| body | `px-cdn.net` | 4 | |
| body | `PerimeterX` | 4 | |
| body | `Access to this page has been denied` | 4 | block |
| status | 403 | 1 | |

Block responses are frequently JSON containing `appId`, `jsClientSrc`, `vid` and `uuid`. The app id
is `PX` plus a short token and is stable per site — once you have seen it, it is the cheapest
possible identifier. Newer deployments serve the sensor script from first-party paths, so the
`px-cloud.net` / `px-cdn.net` hosts may be absent.

---

## Akamai Bot Manager

| Kind | Signal | Weight | Only on block/challenge |
|---|---|---|---|
| cookie | `_abck` | 5 | |
| cookie | `bm_sz` | 5 | |
| cookie | `ak_bmsc` | 5 | |
| cookie | `bm_sv` | 4 | |
| cookie | `bm_mi` | 3 | |
| header | `server: AkamaiGHost` | 5 | |
| header | `x-akamai-request-id` | 4 | |
| body | `Reference #` | 3 | block |
| body | `You don't have permission to access` | 2 | block |
| body | `akamai` | 2 | |
| status | 403 | 1 | |

`_abck` carries the sensor state. A widely repeated field observation is that a value containing
`~0~` means the sensor was accepted and `~-1~` means it was not. It is a useful smoke test, but it
is not documented behaviour and the format has changed before — do not build control flow on it
without verifying against your own captures.

Akamai deny pages carry a `Reference #`. Log it verbatim; it is the identifier a site operator will
ask for.

---

## Imperva (Incapsula)

| Kind | Signal | Weight | Only on block/challenge |
|---|---|---|---|
| header | `x-iinfo` | 5 | |
| header | `x-cdn: Incapsula` | 5 | |
| cookie | `visid_incap_*` (prefix) | 5 | |
| cookie | `incap_ses_*` (prefix) | 5 | |
| cookie | `nlbi_*` (prefix) | 4 | |
| cookie | `reese84` | 5 | |
| body | `Incapsula incident ID` | 5 | block |
| body | `_Incapsula_Resource` | 5 | |
| body | `Imperva` | 3 | |
| status | 403 | 1 | |

Two generations coexist. Classic Incapsula sets `visid_incap_<siteid>` / `incap_ses_<n>_<siteid>`
and serves scripts from `/_Incapsula_Resource?...`. Advanced Bot Protection (the former Distil
product line) uses the `reese84` token cookie produced by a JS interstitial. You may see either or
both on the same host.

The `Incapsula incident ID` maps to a specific rule on the operator's side. It is the one piece of
information that makes a support request actionable.

---

## Kasada

| Kind | Signal | Weight | Only on block/challenge |
|---|---|---|---|
| header | `x-kpsdk-ct` | 5 | |
| header | `x-kpsdk-cd` | 5 | |
| header | `x-kpsdk-v` | 4 | |
| header | `x-kpsdk-r` | 4 | |
| body | `149e9513-01fa-4fb0-aad4-566afd725d1b` | 5 | |
| body | `kpsdk` | 4 | |
| status | 429 | 1 | |

Two things make Kasada distinctive:

1. **A rejected request commonly comes back as HTTP 429 with a very short or empty body.** This is
   the single most misdiagnosed response in this guide — people read 429, assume rate limiting, add
   a sleep, and wait forever. A 429 with no `Retry-After` and no rate-limit headers deserves a look
   at the `x-kpsdk-*` family.
2. The client script has commonly been served from a path beginning with the constant GUID
   `149e9513-01fa-4fb0-aad4-566afd725d1b`. That is a strong tell when present, but it is a
   deployment detail and can change.

The `x-kpsdk-*` headers appear on requests made by the SDK as well as on responses, so check both
directions if you are reading a browser capture.

---

## AWS WAF

| Kind | Signal | Weight | Only on block/challenge |
|---|---|---|---|
| cookie | `aws-waf-token` | 5 | |
| header | `x-amzn-waf-action` | 5 | |
| body | `awswaf.com` | 5 | |
| body | `aws-waf-token` | 3 | |
| header | `x-amz-cf-id` | 1 | |
| header | `server: CloudFront` | 1 | |
| status | 202, 403, 405 | 1 | |

Status codes vary by rule action and configuration. A plain **Block** action returns `403` with a
short body. The **Challenge** and **CAPTCHA** actions serve an interstitial, and both `202` and
`405` have been observed for those. Key on the `awswaf.com` host in the body and the
`aws-waf-token` cookie, not the status.

CloudFront headers on their own say nothing about whether WAF is enabled — that is why they are
weighted 1. Plenty of sites are fronted by CloudFront with no WAF at all.

---

## Queue-it

| Kind | Signal | Weight | State |
|---|---|---|---|
| url | `queue-it.net` | 5 | queue |
| cookie | `QueueITAccepted*` (prefix) | 5 | queue |
| cookie | `Queue-it*` (prefix) | 4 | queue |
| body | `queue-it.net` | 4 | queue |
| body | `You are now in line` | 3 | queue |
| body | `waiting room` | 2 | queue |

Not an anti-bot product. It is a virtual waiting room used to cap concurrency during traffic peaks,
and it is in this reference only because it is so often misread as a block. The typical shape is a
`302` to `https://<customer>.queue-it.net/?c=<customer>&e=<event>&t=<your original URL>`.

Retrying harder is actively counterproductive: a new request issues a new token and puts you back
at the end of the line.

---

## Adjacent systems you may run into

Not covered by `detect.py`, but worth recognising so you do not misattribute them:

| System | Tell |
|---|---|
| F5 BIG-IP (LTM / ASM) | `BIGipServer<pool>` cookie, `TS<hex>` cookies |
| Sucuri | `x-sucuri-id`, `x-sucuri-cache` headers, "Access Denied - Sucuri Website Firewall" |
| Reblaze | `rbzid` / `rbzsessionid` cookies |
| Fastly | `x-served-by`, `x-cache`, `x-timer` headers — a CDN, not a bot manager on its own |

If you have solid, reproducible signatures for any of these, they are exactly the kind of
contribution this repo wants. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Capturing a new signature safely

Do this on a site you are permitted to query, from your own browser, with your own account or none
at all.

1. Open DevTools → **Network** before you trigger the block. Tick **Preserve log**; challenge flows
   redirect and you will otherwise lose the interesting response.
2. Reproduce the block. Often it is enough to open the page in a fresh private window over a
   different network, or to request a URL your normal browsing would not hit.
3. Select the blocked request and record, from the **Headers** panel:
   - the status code,
   - every response header name (values only where they are not secrets — `server`, `x-cdn`,
     `cf-mitigated` are fine; anything token-shaped is not),
   - the **names** of every `Set-Cookie`, never the values.
4. From the **Response** panel, record short, stable-looking body substrings: a `<title>`, a script
   `src` path, a vendor host name, a visible error string. Avoid anything containing a per-request
   id.
5. Note whether the marker appears on *every* response from that site or only on the blocked one.
   That distinction is the difference between a weight of 5 and a weight of 4.

### What never goes into a signature

- Cookie **values**, tokens, ray ids, incident ids, session ids, `vid`/`uuid` values
- Your IP address, proxy endpoints, credentials
- The name or URL of the site you captured it on
- Anything you had to log in to see

A signature should be a short, boring substring. If a proposed marker contains something that looks
random, it is a per-request value and it will not match anything twice anyway.
