# AGENTS.md

This file is written to help AI-powered code assistants understand the project quickly and completely.

## Project Overview

**Fully automated** management of Huawei Cloud ELB SSL certificates with Let's Encrypt.
A Python script running daily on FunctionGraph (serverless) obtains a certificate, uploads it to
Huawei ELB, and updates the existing certificate if present. The certificate is also saved as a
hosted certificate in CCM (Cloud Certificate Manager) so it can be downloaded or used by other
Huawei Cloud services. The certificate is also deployed to CDN (Content Delivery Network) domains
that match the certificate domain list. No manual intervention is required.

Two challenge types are supported:
- **DNS-01 challenge** (`letsencrypt_dns.py`): Uses Huawei Cloud DNS or Cloudflare DNS TXT records.
  Wildcard certificates are supported.
- **HTTP-01 challenge** (`letsencrypt_http.py`): Uses ELB L7 policies (FIXED_RESPONSE) on port 80.
  No DNS provider needed. Wildcard certificates are NOT supported.

## Architecture

### DNS-01 Challenge (letsencrypt_dns.py)

```
                  Timer Trigger (daily 3 AM)
                          |
                          v
                  FunctionGraph (Python3.10)
                  letsencrypt-dns-{domain} function
                          |
          +-------+-------+-------+-------+
          |       |       |       |       |
          v       v       v       v       v
   Huawei DNS  Let's   Huawei  Huawei  Huawei
   /Cloudflare Encrypt  ELB     CCM     CDN
   (TXT record) (ACME)  (cert)  (hosted (domain
                                       cert)  match)
```

### HTTP-01 Challenge (letsencrypt_http.py)

```
                  Timer Trigger (daily 3 AM)
                          |
                          v
                  FunctionGraph (Python3.10)
                  letsencrypt-http-{domain} function
                          |
          +-------+-------+-------+-------+
          |       |       |       |       |
          v       v       v       v       v
   Huawei ELB  Let's   Huawei  Huawei  Huawei
   (port 80,   Encrypt  ELB     CCM     CDN
    L7 policy) (ACME    (cert)  (hosted (domain
                HTTP-01)         cert)  match)
```

**HTTP-01 Flow:**
1. Is there a certificate matching the domain in ELB? (searches all ELBs, ELB-independent)
2. If present and valid for >30 days -> skip renewal (rate limit protection)
3. Obtain a new certificate via Let's Encrypt HTTP-01 challenge:
   - Ensure `enhance_l7policy_enable=true` on the listener (enable via PUT if false)
   - Shift all existing L7 policies on the listener +100 in priority
   - For each domain, create an L7 policy (FIXED_RESPONSE) at priority 1 on the HTTP listener (port 80)
   - The policy returns `200 text/plain <key_authorization>` for the challenge path
   - Let's Encrypt validates by requesting `http://<domain>/.well-known/acme-challenge/<token>`
   - The L7 policy intercepts this request and returns the fixed response
4. Upload to ELB:
   - If present -> update (cert ID unchanged, listeners auto-updated)
   - If absent -> create (only upload to ELB certificates, no listener binding)
4b. Upload to CCM (Cloud Certificate Manager) as a hosted certificate (non-fatal)
4c. Deploy to CDN domains matching the certificate domain list (non-fatal, skipped if no match)
5. Find and report the listeners using this certificate
6. Cleanup: delete all L7 policies created for the challenge, restore original priorities (in `finally` block)

**DNS-01 Flow:**
1. Is there a certificate matching the domain in ELB? (searches all ELBs, ELB-independent)
2. If present and valid for >30 days -> skip renewal (rate limit protection)
3. Obtain a new certificate via Let's Encrypt DNS-01 challenge
4. Upload to ELB:
   - If present -> update (cert ID unchanged, listeners auto-updated)
   - If absent -> create (only upload to ELB certificates, no listener binding)
4b. Upload to CCM (Cloud Certificate Manager) as a hosted certificate (non-fatal)
4c. Deploy to CDN domains matching the certificate domain list (non-fatal, skipped if no match)
5. Find and report the listeners using this certificate

## File Structure

```
opencode-project/
  letsencrypt_dns.py              # DNS-01 MAIN SCRIPT - FunctionGraph function code
  letsencrypt_http.py             # HTTP-01 MAIN SCRIPT - FunctionGraph function code
  setup_letsencrypt_fg.py         # DNS-01 setup wizard (English)
  setup_letsencrypt_fg_tr.py      # DNS-01 setup wizard (Turkish)
  setup_letsencrypt_http_fg.py    # HTTP-01 setup wizard (English)
  setup_letsencrypt_http_fg_tr.py # HTTP-01 setup wizard (Turkish)
  AGENTS.md                       # This file - project documentation for AI assistants
  README.md                       # English README
  README_TR.md                    # Turkish README
  letsencrypt_dns_{domain}.py     # DNS-01 domain-specific copies (e.g. letsencrypt_dns_example-com.py)
  letsencrypt_http_{domain}.py    # HTTP-01 domain-specific copies (e.g. letsencrypt_http_example-com.py)
  credentials.csv                 # (Optional) CSV with AK/SK for auto-import (headers: User Name,Access Key Id,Secret Access Key)
```

## letsencrypt_dns.py - DNS-01 Main Script

### Important Design Decisions

- **OpenSSL via ctypes**: No `pip install` needed, `libcrypto` is loaded directly in the FunctionGraph runtime
- **requests library**: Available in the FunctionGraph Python3.10 runtime
- **No AK/SK**: FunctionGraph obtains a token via agency (xrole), no hardcoded credentials
- **Event override**: Timer trigger sends an empty event (default config is used),
  manual invoke can override all config via the event
- **Wildcard support**: Wildcard certificates in `*.domain.com` format are supported.
  In DNS-01 challenge the TXT record is written to the base domain (`_acme-challenge.domain.com.`)
- **Multi-value TXT records**: When both `*.domain` and `domain` are in the SAN list (wildcard),
  they share the same TXT record name. The `create_txt_record` method adds the new value to the
  existing recordset (via PUT) instead of deleting and recreating it. This avoids DNS cache issues
  where Let's Encrypt's secondary validation sees a stale cached value.

### Components

| Class / Function | Role |
|---|---|
| `OpenSSLWrapper` | ctypes with libcrypto: generate RSA key, create CSR, sign SHA256 |
| `ACMEClient` | RFC 8555 ACME protocol: register, order, challenge, finalize, download |
| `HuaweiDNSClient` | DNS REST API: create/delete TXT records (DNS-01 challenge) |
| `CloudflareDNSClient` | Cloudflare REST API: create/delete TXT records (DNS-01 challenge) |
| `HuaweiELBClient` | ELB v3 REST API: cert list/create/update, listener search/bind |
| `HuaweiCCMClient` | CCM (SCM) REST API: hosted cert import/list/delete (for download/use by other services) |
| `HuaweiCDNClient` | CDN REST API: list domains, deploy certificate to matching CDN domains |
| `handler(event, context)` | FunctionGraph entry point - orchestrates the entire flow |

### Config (overridable via event)

| Parameter | Default | Description |
|---|---|---|
| `DOMAIN` | `example.com` | Primary domain |
| `DOMAINS` | `["example.com", "www.example.com"]` | SAN list (`["*.domain", "domain"]` for wildcard) |
| `ZONE_ID` | `ff80...416ef` | Huawei DNS zone ID |
| `ZONE_NAME` | `example.com.` | Huawei DNS zone name (may differ from domain for subdomains) |
| `CERT_NAME` | `elb-ssl-test` | Name to use when creating a new cert |
| `REGION` | `tr-west-1` | Huawei Cloud region |
| `PROJECT_ID` | `b199...59e1` | Fallback project ID (auto-detected from agency token) |
| `ACME_DIRECTORY_URL` | `https://acme-v02.api...` | Let's Encrypt production endpoint |
| `RENEW_BEFORE_DAYS` | `30` | Renew if fewer than this many days remain |
| `DNS_PROVIDER` | `huawei` | DNS provider: `huawei` or `cloudflare` |
| `CLOUDFLARE_API_TOKEN` | `` | Cloudflare API token (required if DNS_PROVIDER=cloudflare) |
| `CLOUDFLARE_ZONE_ID` | `` | Cloudflare zone ID (required if DNS_PROVIDER=cloudflare) |
| `CCM_ENABLED` | `True` | Also save certificate to CCM (Cloud Certificate Manager) as a hosted cert |
| `CCM_CERT_NAME` | `` | CCM cert name (empty = use CERT_NAME) |
| `CCM_REGION` | `ap-southeast-1` | CCM region (CCM is only in cn-north-4, ap-southeast-1, my-kualalumpur-1) |
| `CDN_ENABLED` | `True` | Also deploy certificate to CDN domains matching the cert domain list |
| `CDN_CERT_NAME` | `` | CDN certificate name (empty = use CERT_NAME) |
| `force_renew` | `false` | If passed via event, skip expiry check |

## letsencrypt_http.py - HTTP-01 Main Script

### Important Design Decisions

- **No DNS provider needed**: The challenge is served via ELB L7 policy (FIXED_RESPONSE) on port 80
- **L7 policy per challenge**: For each domain's authorization, a separate L7 policy is created
  with a PATH rule matching `/.well-known/acme-challenge/<token>` and a FIXED_RESPONSE returning
  the key authorization as `200 text/plain`
- **Inline rules**: L7 rules are created inline with the policy (single API call)
- **Priority shift**: Before creating challenge policies, all existing L7 policies on the listener
  are shifted +100 in priority (via PUT, only the priority field is updated — policies are not
  deleted/recreated). Challenge policies are then created at `priority: 1` (highest).
  After the challenge (in `finally`), challenge policies are deleted and existing policies are
  restored to their original priorities. This works with any existing policies (e.g. K8s ingress
  redirects) without manual configuration.
- **enhance_l7policy_enable auto-enable**: `fixed_response_config` requires
  `enhance_l7policy_enable=true` on the listener. The function checks this before the challenge
  and enables it via PUT if false. The setup wizard also checks and enables it.
- **Cleanup in finally**: All L7 policies are deleted and priorities restored in the `finally` block, even on error
- **No wildcard**: HTTP-01 challenge does not support wildcard certificates
- **OpenSSL via ctypes**: Same as DNS-01 version, no pip package needed

### Components

| Class / Function | Role |
|---|---|
| `OpenSSLWrapper` | ctypes with libcrypto: generate RSA key, create CSR, sign SHA256 |
| `ACMEClient` | RFC 8555 ACME protocol with HTTP-01: `get_http_challenge`, `compute_http_challenge` |
| `HuaweiELBClient` | ELB v3 REST API: cert list/create/update, listener search, L7 policy CRUD |
| `HuaweiCCMClient` | CCM (SCM) REST API: hosted cert import/list/delete (for download/use by other services) |
| `HuaweiCDNClient` | CDN REST API: list domains, deploy certificate to matching CDN domains |
| `handler(event, context)` | FunctionGraph entry point - orchestrates the HTTP-01 flow |

### Config (overridable via event)

| Parameter | Default | Description |
|---|---|---|
| `DOMAIN` | `example.com` | Primary domain |
| `DOMAINS` | `["example.com"]` | SAN list (NO wildcard - HTTP-01 doesn't support it) |
| `CERT_NAME` | `letsencrypt-example-com` | Name to use when creating a new cert |
| `REGION` | `tr-west-1` | Huawei Cloud region |
| `PROJECT_ID` | `your-project-id-here` | Fallback project ID (auto-detected from agency token) |
| `HTTP_LISTENER_ID` | `your-http-listener-id-here` | ID of the port 80 HTTP listener (determined by setup) |
| `ACME_DIRECTORY_URL` | `https://acme-v02.api...` | Let's Encrypt production endpoint |
| `ACCOUNT_EMAIL` | `mailto:admin@example.com` | ACME account email |
| `RENEW_BEFORE_DAYS` | `30` | Renew if fewer than this many days remain |
| `CCM_ENABLED` | `True` | Also save certificate to CCM (Cloud Certificate Manager) as a hosted cert |
| `CCM_CERT_NAME` | `` | CCM cert name (empty = use CERT_NAME) |
| `CCM_REGION` | `ap-southeast-1` | CCM region (CCM is only in cn-north-4, ap-southeast-1, my-kualalumpur-1) |
| `CDN_ENABLED` | `True` | Also deploy certificate to CDN domains matching the cert domain list |
| `CDN_CERT_NAME` | `` | CDN certificate name (empty = use CERT_NAME) |
| `force_renew` | `false` | If passed via event, skip expiry check |

### Manual Invoke Example via Event

```json
{
  "domain": "example.com",
  "domains": ["example.com", "www.example.com"],
  "cert_name": "letsencrypt-example-com",
  "http_listener_id": "cd58...",
  "force_renew": true
}
```

### ELB L7 Policy API (v3)

| Operation | Endpoint | Method |
|---|---|---|
| Create policy | `/v3/{project_id}/elb/l7policies` | POST |
| List policies | `/v3/{project_id}/elb/l7policies?listener_id={id}` | GET |
| Delete policy | `/v3/{project_id}/elb/l7policies/{policy_id}` | DELETE |

**Create L7 Policy body:**
```json
{
  "l7policy": {
    "listener_id": "<listener_id>",
    "action": "FIXED_RESPONSE",
    "name": "acme-challenge-<token_short>",
    "priority": 1,
    "fixed_response_config": {
      "status_code": "200",
      "content_type": "text/plain",
      "message_body": "<key_authorization>"
    },
    "rules": [
      {
        "type": "PATH",
        "compare_type": "EQUAL_TO",
        "value": "/.well-known/acme-challenge/<token>"
      }
    ]
  }
}
```

**Important API details:**
- `fixed_response_config` field is `message_body` (NOT `body`)
- `position` is deprecated/unsupported; use `priority` (smaller = higher priority, range 1-10000)
- `fixed_response_config` requires `enhance_l7policy_enable=true` on the listener
- Rules can be created inline with the policy via the `rules` array
- Deleting a policy automatically deletes its rules

## setup_letsencrypt_fg.py - DNS-01 Setup Wizard

Works with AK/SK (KooCLI not required), asks all parameters interactively.
Creates domain-specific resources for each domain (function, timer, cert names include the domain).
The same setup script can be run repeatedly for different domains; it does not overwrite previous
domains' resources.

### CSV Credentials Auto-Import

If a `.csv` file exists in the script directory with headers `User Name,Access Key Id,Secret Access Key`,
the wizard automatically imports the AK/SK from the first data row. The user can press Enter to accept
or type to override. The detected username and masked AK are displayed as info.

### Steps

1. Obtain IAM token (with AK/SK) - both project-scoped and domain-scoped tokens
2. Validate DNS zone and ELB (ELB name is not asked, only existence check).
   DNS zone lookup tries the exact domain first, then falls back to parent domains
   (e.g. `test1.batur.site` -> `batur.site.`)
   For Cloudflare DNS, the zone is looked up via Cloudflare API (token required).
3. Create IAM custom policy (DNS + ELB + CCM + CDN permissions, with domain-scoped token)
4. Create IAM agency (trust to FunctionGraph, `trust_domain_name: op_svc_cff`)
5. Assign policy to agency (all-projects, `/inherited_to_projects` suffix)
6. Create FunctionGraph function (with agency + code)
7. Upload function code (config applied in memory, original file unchanged)
8. Add timer trigger (cron)
9. Save domain-specific script copy (`letsencrypt_dns_{domain}.py`)
10. (Optional) Invoke the function - first certificate issuance (~60 seconds)

### Domain-Specific Default Names (DNS-01)

For domain `example.com` (`domain_slug = example-com`):

| Resource | Default |
|---|---|
| Function | `letsencrypt-dns-example-com` |
| Timer | `daily-cert-renewal-example-com` |
| Cert | `letsencrypt-example-com` |
| Policy | `letsencrypt-example-com-policy` |
| Copy | `letsencrypt_dns_example-com.py` |

The agency (`fg-letsencrypt`) is shared - a single agency can serve multiple functions.

## setup_letsencrypt_http_fg.py - HTTP-01 Setup Wizard

Works with AK/SK (KooCLI not required). No DNS provider needed.
The wizard resolves the domain's public IP and matches it to an ELB in the cloud account.
If no ELB matches, the script exits (HTTP-01 won't work).
If matched, finds the port 80 HTTP listener and passes its ID to the function.

### Steps

1. Obtain IAM token (with AK/SK) - both project-scoped and domain-scoped tokens
2. Ask domain (wildcard not supported - HTTP-01 limitation)
3. Resolve domain IP via `socket.gethostbyname()`
4. List all ELBs, find the one whose `vip_address` or `publicips` matches the domain IP
   - If no match -> exit with message ("HTTP-01 challenge will NOT work")
5. Find port 80 HTTP listener on the matched ELB
   - If no port 80 listener -> exit
   - If listener protocol is not HTTP (e.g. TCP) -> exit (L7 policies need HTTP)
   - If `enhance_l7policy_enable` is false -> enable via PUT (exit if cannot)
6. Check existing L7 policies on the listener (info only, function handles priority shift)
7. Create IAM custom policy (ELB + CCM + CDN permissions: `elb:*:*` + `scm:*:*` + `cdn:*:*`)
8. Create IAM agency (trust to FunctionGraph, `trust_domain_name: op_svc_cff`)
9. Assign policy to agency (all-projects, `/inherited_to_projects` suffix)
10. Create FunctionGraph function (with agency + code)
11. Upload function code (config applied in memory, original file unchanged)
12. Add timer trigger (cron)
13. Save domain-specific script copy (`letsencrypt_http_{domain}.py`)
14. (Optional) Invoke the function - first certificate issuance (~60 seconds)

### Domain-Specific Default Names (HTTP-01)

For domain `example.com` (`domain_slug = example-com`):

| Resource | Default |
|---|---|
| Function | `letsencrypt-http-example-com` |
| Timer | `daily-cert-renewal-http-example-com` |
| Cert | `letsencrypt-example-com` |
| Policy | `letsencrypt-http-example-com-policy` |
| Copy | `letsencrypt_http_example-com.py` |

The agency (`fg-letsencrypt`) is shared - a single agency can serve multiple functions.

### IAM Permissions (HTTP-01)

```
ELB: elb:*:*
CCM: scm:*:*
CDN: cdn:*:*
```

No DNS permissions needed (no DNS-01 challenge).

### Domain-to-ELB Matching

The setup resolves the domain to an IP address and compares it with all ELBs:
- `vip_address` field on the loadbalancer object
- `publicips[*].publicip_address` field (list of public IPs)

If the domain IP matches an ELB, the setup finds the port 80 listener on that ELB
(`protocol_port == 80` and `protocol == "HTTP"`).

## Common Setup Details (both DNS-01 and HTTP-01)

### Wildcard Certificate (DNS-01 only)

When the DNS-01 wizard asks "Wildcard certificate?" and the answer is `y`, the domain list is
set to `["*.domain", "domain"]`. This covers all subdomains and the apex domain.
HTTP-01 does NOT support wildcard certificates.

### Cloudflare DNS (DNS-01 only)

When the DNS-01 wizard asks "DNS provider", choosing `2` (Cloudflare DNS) switches the DNS-01
challenge to use Cloudflare's REST API instead of Huawei DNS. The wizard asks for:

1. **Cloudflare API Token** - requires `Zone:DNS:Edit` permission for the target zone.
   Create at: `https://dash.cloudflare.com/profile/api-tokens`
2. **Cloudflare Zone ID** - auto-detected if blank (queries Cloudflare API by domain name,
   with parent domain fallback like Huawei DNS)

The API token is embedded in the function code (uploaded to FunctionGraph). This is necessary
because FunctionGraph's Huawei agency cannot obtain Cloudflare credentials. The IAM policy
still includes DNS + ELB permissions (the agency is shared across domains).

Cloudflare API: `https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records`
Auth header: `Authorization: Bearer {api_token}`

### IAM Endpoints (Region-Specific)

All IAM APIs use a region-specific endpoint: `https://iam.{region}.myhuaweicloud.com`

| Operation | Endpoint | Method |
|---|---|---|
| Create/list agency | `/v3.0/OS-AGENCY/agencies` | POST/GET |
| Create custom policy | `/v3.0/OS-ROLE/roles` | POST |
| Assign policy -> agency | `/v3.0/OS-INHERIT/domains/{domain_id}/agencies/{agency_id}/roles/{role_id}/inherited_to_projects` | PUT |

### IAM Permissions

| Challenge | Permissions |
|---|---|
| DNS-01 | `dns:*:*` + `elb:*:*` + `scm:*:*` + `cdn:*:*` |
| HTTP-01 | `elb:*:*` + `scm:*:*` + `cdn:*:*` |

### Token Strategy

- **Project-scoped token**: For DNS, ELB, FunctionGraph operations
- **Domain-scoped token**: For IAM policy, agency, role association (admin operations require domain scope)

### FunctionGraph Endpoints

| Operation | Endpoint |
|---|---|
| Create function | `POST /v2/{project_id}/fgs/functions` |
| Upload code | `PUT /v2/{project_id}/fgs/functions/{quote(urn)}/code` |
| Add trigger | `POST /v2/{project_id}/fgs/triggers/{urn}` (URN is NOT encoded!) |
| Invoke | `POST /v2/{project_id}/fgs/functions/{urn}/invocations` |

### Config Application Strategy

The setup scripts do not modify the original `letsencrypt_dns.py` / `letsencrypt_http.py` files. Instead:
1. The original file is read into memory
2. Config is applied in memory via `apply_config_to_content()`
3. The customized content is uploaded to the function
4. A domain-specific copy is saved (`letsencrypt_dns_{domain}.py` / `letsencrypt_http_{domain}.py`)

## Huawei Cloud Resources (Current State)

| Resource | Name | ID | Note |
|---|---|---|---|
| DNS Zone | `example.com.` | `ff80...416ef` | In a different project (`4672...`) |
| HTTPS Listener | `https-listener` | `cd58...27b265` | Port 443, cert: `7de0...` |
| ELB Cert | `letsencrypt-example-com` | `7de0...1077f` | domain: example.com,www.example.com |
| FunctionGraph | `letsencrypt-dns` | URN: `urn:fss:tr-west-1:...:letsencrypt-dns` | Python3.10, 512MB, 600s timeout |
| Agency | `fg-dns-letsencrypt` | - | Attached to function as xrole |
| Timer Trigger | `daily-cert-renewal` | `a43c3bcc-...` | cron `0 0 3 * * ?` (daily at 3 AM) |

**Important:** The DNS zone (`example.com.`) and the ELB are in different projects. Since the DNS API
uses a global endpoint (`dns.myhuaweicloud.com`), it works with a different project token.
But the ELB API is project-scoped, so the agency token's project must match the ELB's project.

## KooCLI (hcloud.exe)

- Path: `C:\koocli\hcloud.exe`
- Version: 6.2.9
- Config: `~/.hcloud/config.json` (AKSK mode, region: tr-west-1)
- Auth: Encrypted AK/SK
- **The setup scripts do not require KooCLI** - they work with AK/SK only

### FunctionGraph Invoke with KooCLI

**Important trap:** koocli wraps the `InvokeFunction` body as `{"": {...}}`.
The function receives the event as `{"": {"domain": ...}}` and `event.get("domain")` returns empty.

**Solution:** Do NOT use a `""` key under `body` in the JSON input; put parameters directly under `body`:

```json
{
  "header": { "X-CFF-Request-Version": "v1", "X-Cff-Log-Type": "tail" },
  "path": {
    "function_urn": "urn:fss:tr-west-1:b199...59e1:function:default:letsencrypt-dns",
    "project_id": "b199...59e1"
  },
  "body": {
    "domain": "example.com",
    "domains": ["example.com"],
    "cert_name": "letsencrypt-example-com"
  }
}
```

Command:
```powershell
hcloud FunctionGraph InvokeFunction --cli-region=tr-west-1 --cli-jsonInput=input.json
```

### ELB API with KooCLI

ELB v3 APIs emit a "multi-version" warning that breaks JSON parsing:
```
ListListeners is a multi-version API, where the version (v3) is default.
```
Filter out this line and extract the JSON.

## Test Scenarios

### DNS-01 Tests

#### 1. Skip test (existing cert valid)
Invoke with empty event -> should return `status: "skip"`, `days_left: 89`.

#### 2. New cert creation (no listener binding)
Send a new domain via event (e.g. `example.com`) -> should return `cert_action: "created"`, `listeners: []`.
Goes to Let's Encrypt production, takes ~55 seconds.

#### 3. Cert renewal (update + listener auto-update)
Invoke the existing domain with `force_renew: true` -> should return `cert_action: "updated"`,
listener list should be non-empty. Cert ID unchanged, listeners auto-updated.

#### 4. Wildcard certificate
Send a wildcard domain via event:
```json
{
  "domain": "example.com",
  "domains": ["*.example.com", "example.com"],
  "cert_name": "letsencrypt-example-com"
}
```
The TXT record is written to `_acme-challenge.example.com.` (no `*.` prefix).

### HTTP-01 Tests

#### 1. Skip test (existing cert valid)
Invoke `letsencrypt_http` with empty event -> should return `status: "skip"`, `days_left: 89`.

#### 2. New cert creation via HTTP-01
Invoke with a domain that resolves to the ELB:
```json
{
  "domain": "example.com",
  "domains": ["example.com"],
  "http_listener_id": "cd58...",
  "cert_name": "letsencrypt-example-com"
}
```
Should return `cert_action: "created"`, `challenge_type: "http-01"`. Takes ~55 seconds.
L7 policies are created and deleted (cleanup) during the run.

#### 3. Cert renewal via HTTP-01
Invoke with `force_renew: true` -> should return `cert_action: "updated"`,
listener list should be non-empty. L7 policies created and cleaned up.

#### 4. Multi-domain via HTTP-01
```json
{
  "domain": "example.com",
  "domains": ["example.com", "www.example.com"],
  "http_listener_id": "cd58..."
}
```
Each domain gets its own L7 policy (different token = different path). All policies cleaned up.

## Things to Watch Out For

1. **Let's Encrypt rate limit**: 50 certs per week for the same domain. Use `force_renew` carefully in tests.
2. **Staging vs Production**: For testing, set `ACME_DIRECTORY_URL` to staging:
   `https://acme-staging-v02.api.letsencrypt.org/directory`
3. **DNS propagation (DNS-01)**: The script uses `wait_for_dns_propagation` with Google DoH (`dns.google/resolve`)
   to wait for the TXT record to propagate. Takes ~20-60 seconds.
4. **OpenSSL version**: Must be tested with the libcrypto in the FunctionGraph Python3.10 runtime.
   OpenSSL 1.1+ APIs such as `RSA_get0_n`, `RSA_get0_e` are used.
5. **Agency permissions**: The function requires DNS + ELB + CCM + CDN (DNS-01) or ELB + CCM + CDN (HTTP-01) permissions in the agency.
   Otherwise `get_token_from_context` obtains a token but API calls return 403.
   Re-running the setup script updates existing IAM policies to add `scm:*:*` (CCM) and `cdn:*:*` (CDN) permissions.
6. **DNS zone project difference (DNS-01)**: The DNS zone may be in a different project; since the DNS API is global it works.
   But the ELB API is project-scoped, so the agency token's project must be the same as the ELB's project.
7. **DNS zone subdomain fallback (DNS-01)**: When a subdomain is given (e.g. `test1.batur.site`), the setup wizard
   looks for a DNS zone matching the exact domain first, then falls back to parent domains (`batur.site.`).
   The matched zone name is stored in `ZONE_NAME` in the generated script.
8. **IAM token scope**: Creating policies/agencies requires a domain-scoped token.
   IAM admin operations with a project-scoped token return 403.
9. **IAM endpoints region-specific**: `iam.myhuaweicloud.com` (global) returns 404 for some IAM APIs.
   Use `iam.{region}.myhuaweicloud.com` (region-specific).
10. **Trigger endpoint**: The URN is NOT URL-encoded; it is placed raw in the path.
    Path: `/fgs/triggers/{urn}` (NOT `/fgs/functions/{quote(urn)}/triggers`)
11. **HTTP-01 wildcard limitation**: HTTP-01 challenge does NOT support wildcard certificates.
    Use DNS-01 for wildcard certs.
12. **HTTP-01 domain-to-ELB requirement**: The domain's DNS A record must point to the ELB's public IP.
    The setup script checks this and exits if no match is found.
13. **HTTP-01 port 80 listener**: The ELB must have an HTTP (not TCP) listener on port 80.
    L7 policies (FIXED_RESPONSE) only work on HTTP/HTTPS listeners.
14. **HTTP-01 L7 policy `message_body`**: The `fixed_response_config` field is `message_body` (NOT `body`).
    Using `body` returns a 400 error: `'body' isn't supported attribute`.
15. **HTTP-01 L7 policy `priority` vs `position`**: Use `priority` (not `position`).
    `position` is deprecated/unsupported. Smaller priority = higher priority.
16. **HTTP-01 `enhance_l7policy_enable`**: `fixed_response_config` requires `enhance_l7policy_enable=true`
    on the listener. The function and setup wizard auto-enable it via PUT if false. For shared load balancers, this is unsupported.
17. **HTTP-01 L7 policy cleanup**: L7 policies are deleted and original priorities restored in the `finally` block.
    If the function crashes between creation and cleanup, policies may remain on the listener.
    Re-running the function or manually deleting them is safe.
18. **CCM has no update API**: CCM (Cloud Certificate Manager) does not support updating an imported
    certificate. On renewal, the existing hosted cert is deleted and re-imported (new cert ID).
    If other services reference the CCM cert by ID, they must be re-deployed after renewal.
19. **CCM is non-fatal**: CCM upload errors do not break the main ELB certificate flow.
    The result includes a `ccm` field showing success or error. If CCM permissions are missing,
    the ELB cert still succeeds; only the CCM part fails.
20. **CCM cert name constraints**: CCM cert names must be 3-63 chars (English, digits, `_`, `-`, `.`).
    The default `CERT_NAME` (e.g. `letsencrypt-example-com`) fits. Override via `CCM_CERT_NAME` if needed.
21. **CCM endpoint**: `https://scm.{ccm_region}.myhuaweicloud.com` (region-specific, NOT global — service code `scm`, formerly SSL Certificate Manager).
    CCM is only available in `cn-north-4&` `ap-southeast-1`, `my-kualalumpur-1`. Uses the same agency token as ELB.
22. **CDN is non-fatal**: CDN deploy errors do not break the main ELB certificate flow.
    The result includes a `cdn` field showing success or error. If CDN permissions are missing,
    the ELB cert still succeeds; only the CDN part fails.
23. **CDN requires existing domains**: The certificate is deployed to CDN domains that match the
    certificate domain list. If no matching CDN domain exists, the CDN step is skipped
    (`action: "skip"`). CDN domains must be created separately in the CDN console.
24. **CDN API is global**: `https://cdn.myhuaweicloud.com` (no region prefix). Available in
    `cn-north-1` and `ap-southeast-1`. Uses the same agency token as ELB.
    List domains: `GET /v1.0/cdn/domains`. Update cert: `PUT /v1.0/cdn/domains/config-https-info`.
    Both APIs require `enterprise_project_id=all` query parameter to see domains across all enterprise projects.
25. **CDN wildcard matching**: If the certificate is for `*.example.com`, all CDN domains ending
    with `.example.com` (and `example.com` itself) are updated. Up to 50 domains per API call.

## Code Style

- English comments (UTF-8)
- `# ===` section separator
- Global config variables in UPPERCASE
- Event override uses the same variables in lowercase (cfg_domain, cfg_domains, ...)
- Error handling: try/except returns traceback, finally performs cleanup (DNS TXT or L7 policy)
- No pip packages (only `requests` and `ctypes` with stdlib)
