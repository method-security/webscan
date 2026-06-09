# SOHO Router Corpus — Favicon & Admin-Page Hashes

This directory contains two corpus files used by the SOHO router enumeration
stage to fingerprint consumer and ISP-deployed SOHO routers based on observable
HTTP characteristics.

## Files

| File | Purpose |
|------|---------|
| `favicon_hashes.json` | mmh3 favicon hashes for router identification |
| `admin_page_hashes.json` | SHA-256 hashes of canonicalized admin page HTML bodies |

---

## `favicon_hashes.json`

### Schema

Each key is the mmh3 hash as a **signed 32-bit decimal integer string** (the
format Shodan uses for `http.favicon.hash`).

```json
{
  "favicon_hashes": {
    "<mmh3-signed-int>": {
      "vendor": "tplink | asus | netgear | dlink | isp-cpe | dd-wrt",
      "product": "<product-id>",
      "models": ["<model-1>", "..."],
      "firmware_range": "<version range or 'all'>",
      "notes": "<human-readable source/verification notes>",
      "shodan_verified": true | false,
      "shodan_count_approx": <integer>,
      "shodan_query": "<shodan search query used to verify>"
    }
  }
}
```

### Hash Computation (mmh3)

The Shodan mmh3 favicon hash is computed as:

```python
import mmh3, base64, requests

resp = requests.get("http://<router-ip>/favicon.ico")
favicon_data = resp.content
favicon_b64 = base64.encodebytes(favicon_data).decode()  # note: encodebytes not b64encode
hash_val = mmh3.hash(favicon_b64)  # signed 32-bit integer
```

**Important**: Use `base64.encodebytes` (which inserts `\n` every 76 chars), NOT
`base64.b64encode`. This matches Shodan's implementation.

### Coverage

| Vendor | Hashes | Notes |
|--------|--------|-------|
| TP-Link | 5 | DD-WRT shared firmware + Omada + corporate + cloud |
| Asus | 5 | ASUSWRT + ASUSWRT-Merlin + corporate |
| Netgear | 5 | ProSafe + DGND + Nighthawk + Genie + corporate |
| D-Link | 5 | DIR series + DSL + corporate |
| ISP CPE | 5 | Arcadyan + Sercomm + Compal + generic null |

---

## `admin_page_hashes.json`

### Schema

Each key is the **lowercase hex SHA-256** of the canonicalized admin page HTML body.

```json
{
  "admin_page_hashes": {
    "<sha256-hex>": {
      "vendor": "tplink | asus | netgear | dlink | isp-cpe",
      "product": "<product-id>",
      "model": "<model name>",
      "hardware_version": "<hw rev or 'unknown'>",
      "firmware_build": "<build number or 'unknown'>",
      "firmware_version": "<version string or 'unknown'>",
      "page_url": "<URL path fetched (e.g. / or /Main_Login.asp)>",
      "page_title": "<HTML title text>",
      "page_body_length": <integer bytes of raw body>,
      "source": "live-device-capture | firmware-analysis",
      "notes": "<provenance: IP, ASN, confirmation method>",
      "references": ["<optional CVE or URL>"]
    }
  }
}
```

### Hash Computation

Admin page hashes use **canonicalized SHA-256** to survive minor per-session
dynamic content (session tokens, CSRF nonces, uptime counters, etc.).

```python
import hashlib, re, requests

resp = requests.get("http://<router-ip>/", timeout=10)
body = resp.text

# 1. Strip inline JavaScript variable assignments (session tokens, etc.)
body = re.sub(r'var\s+\w+\s*=\s*["\'][^"\']*["\'];', '', body)

# 2. Normalize form field values (CSRF tokens, hidden inputs)
body = re.sub(r'value=["\'][^"\']*["\']', 'value=""', body)

# 3. Collapse whitespace
body = re.sub(r'\s+', ' ', body).strip()

sha256 = hashlib.sha256(body.encode('utf-8')).hexdigest()
```

Use the **same page URL** as the corpus entry (`page_url` field). Most vendors
serve the login page at `/`; ASUSWRT serves it at `/Main_Login.asp`.

### Coverage

| Vendor | Hashes | Min per vendor | All from live devices? |
|--------|--------|---------------|----------------------|
| TP-Link | 11 | 10 ✓ | Yes |
| D-Link | 11 | 10 ✓ | Yes |
| Asus | 11 | 10 ✓ | Yes |
| Netgear | 10 | 10 ✓ | Yes |
| ISP CPE | 9 | 5 ✓ | Yes (Arcadyan + Netgear Orbi ISP) |

All hashes are sourced from live Shodan-discovered devices unless noted
otherwise. Hashes with `source: "live-device-capture"` were captured using the
canonicalization method above and confirmed to contain vendor-identifying HTML.

---

## Vendor Classes

| ID | Description | Key Products |
|----|-------------|-------------|
| `tplink` | TP-Link stock firmware | TL-WR1043ND, Archer C5/C8/C9/C1900, AX21 |
| `asus` | ASUSWRT / ASUSWRT-Merlin | GT-AC5300, GT-AC2900, GT-AX11000, TUF-AX3000/5400, RT-AC3100 |
| `netgear` | Netgear stock firmware | WNR/WNDR series, DGN2200/3700, R6700/R7800, Orbi RBR, WAC124 |
| `dlink` | D-Link stock firmware | DIR-600/610/850, DSL gateways |
| `isp-cpe` | ISP-deployed residential CPE | Arcadyan (Comcast XB), Netgear Orbi (AT&T), Sercomm, Compal |
| `dd-wrt` | DD-WRT third-party firmware | Runs on TP-Link Archer C7/A7, Netgear R7800/R7000 |

---

## Updating This Corpus

### Adding a new favicon hash

1. Fetch the favicon from a live device:
   ```bash
   curl -s http://<router-ip>/favicon.ico > /tmp/favicon.ico
   python3 -c "
   import mmh3, base64
   data = open('/tmp/favicon.ico', 'rb').read()
   b64 = base64.encodebytes(data).decode()
   print(mmh3.hash(b64))
   "
   ```

2. Verify with Shodan:
   ```
   http.favicon.hash:<hash> http.title:<vendor>
   ```

3. Add an entry to `favicon_hashes.json` with `shodan_verified: true` and the
   approx result count.

### Adding a new admin page hash

1. Fetch and canonicalize the admin page using the Python snippet above.

2. Note the raw `page_body_length` (before canonicalization) for provenance.

3. Add an entry to `admin_page_hashes.json` with `source: "live-device-capture"`.

4. Rebuild the embedded bundle:
   ```bash
   cd /path/to/webscan
   go run ./scripts/build-embedded-assets.go
   ```

The bundle is automatically rebuilt in CI via `./godelw verify`.

---

## Notes

- **No fake / placeholder hashes**: Every entry in both files corresponds to a
  hash that has been directly computed from real device firmware or from a live
  internet-accessible device confirmed via Shodan. Entries without
  `shodan_verified: true` were computed from official corporate websites or
  firmware images and are marked accordingly.

- **Netgear caveat**: Netgear consumer routers (R6700, R7000, Orbi) rarely
  expose port 80/8080 due to ISP filtering. The admin page hashes in this corpus
  are primarily from residential devices discovered via Shodan on non-standard
  ports, or from AT&T-deployed Orbi units. High-end models like R7000/R8000 are
  under-represented because their admin UIs are behind HTTPS with self-signed
  certs that block plain-HTTP scanning.

- **TP-Link new UI (AX series)**: Devices running the Lua/stok-based UI (Archer
  AX21 and newer) have much shorter login pages (~1200B) compared to the older
  jQuery-based UI (~10,000B). Both UI generations are represented.
