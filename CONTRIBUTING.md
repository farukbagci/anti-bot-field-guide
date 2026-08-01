# Contributing

The main contribution this repo wants is **one more vendor signature**, or a **correction to an
existing one**. Signatures drift; a guide that is 80% accurate is worse than one that is honest
about what it does not know.

Adding a vendor means adding one dict to the `VENDORS` list in [`detect.py`](detect.py) and one
test. No other code changes.

---

## Before you start

Capture the signature yourself, from a site you are permitted to query, following
[SIGNATURES.md → Capturing a new signature safely](SIGNATURES.md#capturing-a-new-signature-safely).

**Never include in a PR:**

- Cookie **values**, tokens, ray ids, incident ids, session ids, `vid` / `uuid` values
- Real IP addresses, proxy endpoints or credentials
- The name or URL of the site you captured the signature on
- Anything you had to log in to see

Use `example.com` and obviously fake placeholders (`PLACEHOLDER`, `0000000000000000-XXX`) in
fixtures. A signature should be a short, boring substring — if a proposed marker looks random, it
is a per-request value and it will never match twice.

---

## Worked example: adding a vendor

Say you keep meeting a product called **Bouncer** and you have confirmed, from your own captures:

- every response from a Bouncer-protected site carries a `x-bouncer-id` header
- a `bnc_sess` cookie is set on ordinary traffic
- the block page contains `Request blocked by Bouncer` and a `bouncer-cdn.example` script host
- blocks come back as `403`

### 1. Add the entry to `VENDORS`

In `detect.py`, append one dict to the module-level `VENDORS` list:

```python
    {
        "name": "Bouncer",
        "slug": "bouncer",
        "product": "Bouncer Bot Shield",
        "inspects": "TLS fingerprint, JS challenge, IP reputation",
        "notes": "Blocks are HTML. The x-bouncer-id header is present on every "
                 "response, including clean ones, so it identifies the product "
                 "but says nothing about whether you are blocked.",
        "next_step": (
            "Check whether the block clears after a pause. If it does not, the "
            "trigger is your client rather than your rate."
        ),
        "signals": [
            {"kind": "header", "name": "x-bouncer-id", "weight": 5},
            {"kind": "cookie", "name": "bnc_sess", "weight": 5},
            {"kind": "body", "contains": "Request blocked by Bouncer", "weight": 5,
             "state": "block"},
            {"kind": "body", "contains": "bouncer-cdn.example", "weight": 4},
            {"kind": "status", "codes": [403], "weight": 1},
        ],
    },
```

### 2. Add a test

In `tests/test_detect.py`:

```python
def test_bouncer_block_page():
    headers = {
        "x-bouncer-id": "PLACEHOLDER",
        "content-type": "text/html",
        "set-cookie": "bnc_sess=PLACEHOLDER; Path=/; Secure",
    }
    body = HTML.format("<h1>Request blocked by Bouncer</h1>")
    result = detect(403, headers, body)
    assert result["vendor"] == "Bouncer"
    assert result["state"] == STATE_BLOCK
```

A second test showing the vendor present on a **clean** response is worth more than a second block
fixture — it proves your weights do not turn "this site uses Bouncer" into "Bouncer is blocking me".

To eyeball a capture before you write the test, save it as a JSON object with `status`, `headers`,
`body` and `url` and replay it — no request is made:

```bash
python detect.py --from-json capture.json --verbose
```

### 3. Add the row to `SIGNATURES.md`

Same table format as the existing vendors, weights included.

### 4. Run the tests

```bash
python -m pytest tests/ -q
```

`test_vendor_entry_is_well_formed` runs against every entry automatically, so a malformed dict
fails immediately.

---

## Signal reference

| Kind | Required keys | Optional |
|---|---|---|
| `header` | `name` | `contains` — substring of the value |
| `cookie` | `name` | `mode: "prefix"` for families like `visid_incap_*` |
| `body` | `contains` | |
| `url` | `contains` — matched against the final URL and every redirect hop | |
| `status` | `codes` — list of ints | |

Every signal takes a `weight` (1–5) and optionally a `state` of `"block"`, `"challenge"` or
`"queue"`.

Matching is case-insensitive for header names, header values, cookie names, body substrings and
URLs. Write `contains` values naturally — `"Just a moment"` is fine, it is lowercased at match time.

### Choosing a weight

| Weight | Use when |
|---|---|
| 5 | Unique to this vendor and present on **any** response from it |
| 4 | Unique to this vendor but only appears on a block or challenge |
| 3 | Strongly associated, small chance of collision |
| 2 | Consistent with this vendor, also seen elsewhere |
| 1 | Weak corroboration only — status codes, generic CDN headers |

Confidence thresholds: **high** at a summed weight of 5+, **medium** at 3–4, **low** at 1–2.

Two rules that keep the output honest:

1. **A `status` signal never identifies a vendor on its own.** Every product here answers with a
   `403` sooner or later, so the matcher requires at least one header, cookie, body or URL match
   before it will name anybody. Give status signals weight 1.
2. **Only set `state` on markers that cannot appear on a normal content response.** A cookie that is
   set on ordinary traffic must not carry `"state": "block"`, or the tool will report a block on a
   page that loaded fine. As a second line of defence the matcher ignores the `state` of any vendor
   whose summed weight stayed below 3, so one weight-2 marker can never announce a block on its
   own — but do not lean on that instead of choosing the marker carefully.

Pick markers that cannot show up in ordinary page copy. `Just a moment...` is a signature;
`just a moment` is a sentence people write. If a candidate marker is a phrase a human might type,
either lengthen it until it is not, or weight it 2 and let the cookies and headers do the work.

### Marking uncertainty

If a marker is real but inconsistent, say so in `notes` rather than dropping it or overweighting
it. "Present on many but not all deployments" is a useful sentence. A reader who finds one wrong
claim stops trusting the whole table, so hedged and correct beats confident and wrong.

---

## Other contributions

Also welcome:

- **Corrections.** A cookie that was renamed, a status code that changed, a claim that is simply
  wrong. Open an issue with what you observed and what you expected — no PR needed.
- **The Turkish README.** [`README.tr.md`](README.tr.md) tracks `README.md`. If you change one,
  change the other, or say in the PR that you could not and it will be handled on merge.
- **Adjacent systems.** The short list at the end of `SIGNATURES.md` (F5, Sucuri, Reblaze, Fastly)
  would benefit from anyone with solid reproducible signatures.

## Out of scope

These will be closed, regardless of how they are framed:

- CAPTCHA-solving service integration
- Credential handling, credential stuffing or account-takeover techniques
- Paywall or access-control circumvention
- Step-by-step evasion recipes for a specific vendor
- Anything targeting a named site

This is a diagnostic guide. It explains what is in front of you so you can decide whether to ask
for API access, slow down, or stop.

## Style

- Standard library only. A dependency needs a genuine justification.
- Python 3.9+ — no `X | None` in annotations unless the module already imports
  `from __future__ import annotations`.
- No network calls in tests, ever. `detect()` is pure so that this stays easy.
- Calm and specific in prose. No marketing language.
