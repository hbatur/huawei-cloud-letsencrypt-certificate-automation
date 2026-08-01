# Huawei Cloud ELB SSL Automation

**Fully automated** management of Let's Encrypt certificates on Huawei Cloud ELB.
A Python function running daily on FunctionGraph (serverless) obtains a certificate, uploads it to
Huawei ELB, and updates the listeners. No manual intervention is required.

Two challenge types are supported:
- **DNS-01** (`letsencrypt_dns.py`): Uses Huawei Cloud DNS or Cloudflare DNS TXT records. Wildcard supported.
- **HTTP-01** (`letsencrypt_http.py`): Uses ELB L7 policies (FIXED_RESPONSE) on port 80. No DNS provider needed.

## Features

- **Fully automatic**: Certificate renewal via daily timer trigger
- **Dual challenge**: DNS-01 (Huawei/Cloudflare DNS) or HTTP-01 (ELB L7 policy)
- **Wildcard support**: Wildcard certificates in `*.domain.com` format (DNS-01 only)
- **Multi-domain**: The same setup script can be run repeatedly for different domains
- **Dual DNS provider**: Huawei Cloud DNS or Cloudflare DNS for DNS-01 challenge
- **No KooCLI required**: Works with AK/SK only, no pip package needed
- **CSV credentials import**: AK/SK auto-imported from a CSV file in the script directory
- **Subdomain zone fallback**: DNS zone lookup falls back to parent domain (e.g. `test1.batur.site` -> `batur.site`)
- **OpenSSL via ctypes**: `libcrypto` is loaded directly, no `pip install` needed
- **ELB-independent**: Certificate is matched by domain, no ELB name needed
- **Rate limit protection**: Certificates valid for >30 days are not renewed

## Architecture

### DNS-01 Challenge

```
                   Timer Trigger (daily 3 AM)
                           |
                           v
                   FunctionGraph (Python3.10)
                   letsencrypt-dns-{domain}
                           |
           +---------------+---------------+
           |               |               |
           v               v               v
    Huawei DNS /     Let's Encrypt    Huawei ELB
    Cloudflare DNS   (ACME DNS-01)    (cert + listener)
    (TXT record)
```

### HTTP-01 Challenge

```
                   Timer Trigger (daily 3 AM)
                           |
                           v
                   FunctionGraph (Python3.10)
                   letsencrypt-http-{domain}
                           |
           +---------------+---------------+
           |               |               |
           v               v               v
    Huawei ELB       Let's Encrypt    Huawei ELB
    (port 80,        (ACME HTTP-01)   (cert + listener)
     L7 policy
     FIXED_RESPONSE)
```

**HTTP-01 Flow:**
1. Find existing cert by domain -> skip if valid for >30 days
2. For each domain, create an L7 policy (FIXED_RESPONSE) on the port 80 listener
   - Policy matches `/.well-known/acme-challenge/<token>` (PATH EQUAL_TO)
   - Returns `200 text/plain <key_authorization>`
3. Let's Encrypt validates by requesting `http://<domain>/.well-known/acme-challenge/<token>`
4. Download certificate -> upload to ELB (update if exists, create if absent)
5. Cleanup: delete all L7 policies (in `finally` block)

## Prerequisites

### DNS-01 Challenge
1. Huawei Cloud account and AK/SK (with IAM admin permissions)
2. DNS public zone created (Huawei Cloud DNS **or** Cloudflare DNS, for the domain)
3. Python 3.x (to run the setup script, not FunctionGraph)
4. If using Cloudflare DNS: a Cloudflare API Token with `Zone:DNS:Edit` permission
   (create at `https://dash.cloudflare.com/profile/api-tokens`)

### HTTP-01 Challenge
1. Huawei Cloud account and AK/SK (with IAM admin permissions)
2. Domain's DNS A record must point to a Huawei ELB's public IP
3. The ELB must have an **HTTP** (not TCP) listener on **port 80**
4. Python 3.x (to run the setup script, not FunctionGraph)
5. No DNS provider or DNS zone needed

## Setup

### DNS-01 Setup

```powershell
python setup_letsencrypt_fg.py
```

The wizard asks all parameters step by step:

```
  Credentials found in 'credentials.csv' (user: H00XXXX, AK: HPUA...QPWJ)
  Press Enter to accept, or type to override.

  Huawei Access Key ID (AK) [***]:
  Huawei Secret Access Key (SK) [***]:
  Region [tr-west-1]:
  Domain [example.com]: example.com
  Wildcard certificate? (*.domain covers all subdomains) [Y/n]: y
  DNS provider [1=Huawei Cloud DNS / 2=Cloudflare DNS] [1]: 2

  Cloudflare DNS selected. You need a Cloudflare API Token
  with 'Zone:DNS:Edit' permission for the relevant zone.
  Create one at: https://dash.cloudflare.com/profile/api-tokens

  Cloudflare API Token [***]:
  Cloudflare Zone ID (blank = find automatically):
  Certificate name [letsencrypt-test1-batur-site]:
  ...
```

### HTTP-01 Setup

```powershell
python setup_letsencrypt_http_fg.py
```

The wizard resolves the domain IP and matches it to an ELB:

```
  Huawei Access Key ID (AK) [***]:
  Huawei Secret Access Key (SK) [***]:
  Region [tr-west-1]:
  Domain [example.com]: example.com

  Note: HTTP-01 challenge does NOT support wildcard certificates.
  Each domain must resolve to the ELB's public IP.

  Additional domains (SAN, comma-separated, blank for none): www.example.com
  Certificate name [letsencrypt-example-com]:
  ...

  [2] Resolving domain IP: example.com
  example.com -> 1.2.3.4

  [3] Finding ELB matching the domain IP
  2 ELB(s) found:
    - my-elb (vip: 10.0.0.1, publicips: ['1.2.3.4'])

  Matched ELB: my-elb (id: xxx)

  [4] Finding port 80 HTTP listener on the matched ELB
  Found listener: http-listener (id: cd58...)
  Protocol: HTTP, Port: 80

  [5] Checking existing L7 policies on the HTTP listener
  No existing L7 policies found. L7 routing is ready.
  ...
```

If the domain IP doesn't match any ELB, the script exits:
```
  ERROR: Domain 'example.com' (1.2.3.4) does not match any ELB.
  HTTP-01 challenge will NOT work because Let's Encrypt cannot reach
  the challenge endpoint via http://example.com/.well-known/acme-challenge/
```

### CSV Credentials File

If a `.csv` file exists in the script directory with the following headers:

```
User Name,Access Key Id,Secret Access Key
```

The wizard automatically detects it and imports the AK/SK from the first data row.
Press Enter to accept the imported credentials, or type to override.

Example CSV (`credentials.csv`):

```csv
User Name,Access Key Id,Secret Access Key
HXXXX,HPUAXXXX,XXXXXXXXXXXX
```

### Setup Steps

#### DNS-01 Setup Steps
1. Obtain IAM token (project-scoped + domain-scoped)
2. Validate DNS zone and ELB
   - Huawei DNS: zone lookup via Huawei DNS API (with parent domain fallback)
   - Cloudflare DNS: zone lookup via Cloudflare API (with parent domain fallback)
3. Create IAM custom policy (`dns:*:*` + `elb:*:*`)
4. Create IAM agency (trust to FunctionGraph)
5. Assign policy to agency (all-projects)
6. Create FunctionGraph function
7. Upload function code (with config applied)
8. Add timer trigger (cron `0 0 3 * * ?`)
9. Save domain-specific script copy
10. (Optional) Invoke the function - first certificate issuance (~60 seconds)

#### HTTP-01 Setup Steps
1. Obtain IAM token (project-scoped + domain-scoped)
2. Ask domain (wildcard not supported)
3. Resolve domain IP via DNS lookup
4. List all ELBs, find the one whose public IP matches the domain IP
   - If no match -> exit (HTTP-01 won't work)
5. Find port 80 HTTP listener on the matched ELB
   - If no port 80 HTTP listener -> exit
6. Check existing L7 policies on the listener (warn about conflicts)
7. Create IAM custom policy (`elb:*:*` only)
8. Create IAM agency (trust to FunctionGraph)
9. Assign policy to agency (all-projects)
10. Create FunctionGraph function
11. Upload function code (with config applied)
12. Add timer trigger (cron `0 0 3 * * ?`)
13. Save domain-specific script copy
14. (Optional) Invoke the function - first certificate issuance (~60 seconds)

### Multiple Domains

Run the same script again for different domains. Separate resources are created for each domain:

| Challenge | Domain | Function | Timer | Cert |
|---|---|---|---|---|
| DNS-01 | `example.com` | `letsencrypt-dns-example-com` | `daily-cert-renewal-example-com` | `letsencrypt-example-com` |
| HTTP-01 | `example.com` | `letsencrypt-http-example-com` | `daily-cert-renewal-http-example-com` | `letsencrypt-example-com` |

The agency (`fg-letsencrypt`) is shared.

## Files

| File | Description |
|---|---|
| `letsencrypt_dns.py` | DNS-01 MAIN SCRIPT - FunctionGraph function code |
| `letsencrypt_http.py` | HTTP-01 MAIN SCRIPT - FunctionGraph function code |
| `setup_letsencrypt_fg.py` | DNS-01 setup wizard (English) |
| `setup_letsencrypt_fg_tr.py` | DNS-01 setup wizard (Turkish) |
| `setup_letsencrypt_http_fg.py` | HTTP-01 setup wizard (English) |
| `setup_letsencrypt_http_fg_tr.py` | HTTP-01 setup wizard (Turkish) |
| `AGENTS.md` | Detailed documentation for AI assistants |
| `README.md` | English README |
| `README_TR.md` | Turkish README |
| `letsencrypt_dns_{domain}.py` | DNS-01 domain-specific copies created by setup |
| `letsencrypt_http_{domain}.py` | HTTP-01 domain-specific copies created by setup |
| `credentials.csv` | (Optional) CSV with AK/SK for auto-import |

## Manual Invoke (Event Override)

You can override config by sending an event from the FunctionGraph console or via API:

### DNS-01

```json
{
  "domain": "example.com",
  "domains": ["*.example.com", "example.com"],
  "cert_name": "letsencrypt-example-com",
  "force_renew": true
}
```

### HTTP-01

```json
{
  "domain": "example.com",
  "domains": ["example.com", "www.example.com"],
  "cert_name": "letsencrypt-example-com",
  "http_listener_id": "cd58...",
  "force_renew": true
}
```

An empty event `{}` uses the default config (the timer trigger sends an empty event).

## Config Parameters

### DNS-01 Config

| Parameter | Default | Description |
|---|---|---|
| `DOMAIN` | `example.com` | Primary domain |
| `DOMAINS` | `["example.com", "www.example.com"]` | SAN list |
| `ZONE_ID` | - | Huawei DNS zone ID |
| `ZONE_NAME` | - | Huawei DNS zone name (may differ from domain for subdomains) |
| `CERT_NAME` | - | Certificate name |
| `REGION` | `tr-west-1` | Huawei Cloud region |
| `ACME_DIRECTORY_URL` | Let's Encrypt production | ACME endpoint |
| `RENEW_BEFORE_DAYS` | `30` | Renewal threshold in days |
| `DNS_PROVIDER` | `huawei` | DNS provider: `huawei` or `cloudflare` |
| `CLOUDFLARE_API_TOKEN` | `` | Cloudflare API token (required if `cloudflare`) |
| `CLOUDFLARE_ZONE_ID` | `` | Cloudflare zone ID (required if `cloudflare`) |
| `force_renew` | `false` | Skip expiry check |

### HTTP-01 Config

| Parameter | Default | Description |
|---|---|---|
| `DOMAIN` | `example.com` | Primary domain |
| `DOMAINS` | `["example.com"]` | SAN list (no wildcard) |
| `CERT_NAME` | - | Certificate name |
| `REGION` | `tr-west-1` | Huawei Cloud region |
| `HTTP_LISTENER_ID` | - | ID of the port 80 HTTP listener |
| `ACME_DIRECTORY_URL` | Let's Encrypt production | ACME endpoint |
| `ACCOUNT_EMAIL` | `mailto:admin@example.com` | ACME account email |
| `RENEW_BEFORE_DAYS` | `30` | Renewal threshold in days |
| `force_renew` | `false` | Skip expiry check |

## Test Scenarios

### DNS-01 Tests

#### Skip (existing cert valid)
Empty event -> `status: "skip"`, `days_left: 89`

#### New cert creation
New domain via event -> `cert_action: "created"`, `listeners: []` (~55 seconds)

#### Cert renewal
`force_renew: true` -> `cert_action: "updated"`, listener list non-empty

#### Wildcard
`domains: ["*.example.com", "example.com"]` -> TXT record written to `_acme-challenge.example.com.`

#### Cloudflare DNS
Set `DNS_PROVIDER` to `cloudflare` (or choose option `2` in the setup wizard). The TXT record
for the DNS-01 challenge is created via Cloudflare API instead of Huawei DNS. The Cloudflare API
token is embedded in the function code (uploaded to FunctionGraph), since the Huawei agency cannot
obtain Cloudflare credentials.

### HTTP-01 Tests

#### Skip (existing cert valid)
Empty event -> `status: "skip"`, `days_left: 89`

#### New cert creation via HTTP-01
```json
{
  "domain": "example.com",
  "domains": ["example.com"],
  "http_listener_id": "cd58...",
  "cert_name": "letsencrypt-example-com"
}
```
-> `cert_action: "created"`, `challenge_type: "http-01"` (~55 seconds)

#### Cert renewal via HTTP-01
`force_renew: true` -> `cert_action: "updated"`, listener list non-empty

#### Multi-domain via HTTP-01
```json
{
  "domain": "example.com",
  "domains": ["example.com", "www.example.com"],
  "http_listener_id": "cd58..."
}
```
Each domain gets its own L7 policy (different token = different path). All policies cleaned up.

## Notes

- **Let's Encrypt rate limit**: 50 certs per week for the same domain. Use `force_renew` carefully.
- **Staging**: For testing, set `ACME_DIRECTORY_URL` to staging.
- **IAM permissions**: AK/SK must have IAM admin permissions (to create policy/agency).
- **DNS zone (DNS-01)**: A public zone must be created for the domain or its parent domain.
  Subdomains automatically fall back to the parent zone (e.g. `test1.batur.site` uses `batur.site.` zone).
  For Cloudflare DNS, the zone is looked up via Cloudflare API.
- **Cloudflare API token (DNS-01)**: Requires `Zone:DNS:Edit` permission for the target zone.
  The token is embedded in the function code (no Huawei agency integration for Cloudflare).
- **ELB**: An HTTPS listener must be created (certificate is matched by domain).
- **HTTP-01 wildcard**: HTTP-01 challenge does NOT support wildcard certificates. Use DNS-01 for wildcard certs.
- **HTTP-01 domain-to-ELB**: The domain's DNS A record must point to the ELB's public IP.
  The setup script checks this and exits if no match is found.
- **HTTP-01 port 80 listener**: The ELB must have an HTTP (not TCP) listener on port 80.
  L7 policies (FIXED_RESPONSE) only work on HTTP/HTTPS listeners.
- **HTTP-01 L7 policy `message_body`**: The `fixed_response_config` field is `message_body` (NOT `body`).
- **HTTP-01 L7 policy `priority`**: Use `priority` (not `position`). `position` is deprecated.
  Smaller priority = higher priority. Range 1-10000.
- **HTTP-01 `enhance_l7policy_enable`**: `fixed_response_config` requires `enhance_l7policy_enable=true`
  on the listener. For shared load balancers, this may be unsupported.
- **HTTP-01 L7 policy cleanup**: L7 policies are deleted in the `finally` block.
  If the function crashes between creation and cleanup, policies may remain on the listener.
  Re-running the function or manually deleting them is safe.

## Technology

- **Python 3.10** (FunctionGraph runtime)
- **requests** (available in FunctionGraph runtime)
- **ctypes** (direct access to OpenSSL libcrypto)
- **Huawei Cloud**: FunctionGraph, DNS, ELB v3, IAM
- **Cloudflare**: DNS REST API (optional, for DNS-01 challenge)
- **Let's Encrypt**: ACME v2 (RFC 8555), DNS-01 and HTTP-01 challenges
