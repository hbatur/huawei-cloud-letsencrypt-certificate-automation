# Installation Guide

Step-by-step installation for fully automated Let's Encrypt SSL certificate management on Huawei Cloud ELB.

---

## 1. Prerequisites

### General (both methods)

| # | Requirement |
|---|---|
| 1 | Huawei Cloud account |
| 2 | AK/SK with IAM admin permissions — My Credentials > Access Keys |
| 3 | Python 3.x (to run the setup script locally, not FunctionGraph) |
| 4 | `requests` library (`pip install requests`) |

### DNS-01 additional

| # | Requirement |
|---|---|
| 5 | DNS public zone (Huawei Cloud DNS **or** Cloudflare DNS) |
| 6 | If using Cloudflare: API Token with `Zone:DNS:Edit` permission |

### HTTP-01 additional

| # | Requirement |
|---|---|
| 5 | Domain A record must point to the ELB's public IP |
| 6 | ELB must have an **HTTP** (not TCP) listener on **port 80** |

---

## 2. Choose Your Method

```
                    Need wildcard?
                         /        \
                       YES         NO
                        |            |
                   DNS-01          Have DNS access?
                 (TXT record)         /        \
                              YES           NO
                               |              |
                           DNS-01         HTTP-01
                         (TXT record)    (ELB L7 policy)
```

| Feature | DNS-01 | HTTP-01 |
|---|---|---|
| Wildcard (`*.domain`) | Yes | No |
| DNS provider | Required | Not needed |
| ELB port 80 listener | Not needed | Required |
| Setup script | `setup_letsencrypt_fg.py` | `setup_letsencrypt_http_fg.py` |

---

## 3. Installation — DNS-01

### 3.1 Run the script

```powershell
python setup_letsencrypt_fg.py
```

### 3.2 Answer the wizard prompts

You'll be asked the following. Values in brackets `[...]` are defaults — press **Enter** to accept.

```
Huawei Access Key ID (AK): HPUAXXXXXXXXXXXX
Huawei Secret Access Key (SK): ********
Region [tr-west-1]:
Domain: example.com
Wildcard certificate? (*.domain covers all subdomains) [Y/n]: y
DNS provider [1=Huawei Cloud DNS / 2=Cloudflare DNS] [1]: 1
Certificate name [letsencrypt-example-com]:
```

**If you choose Cloudflare**, you'll also be asked:
```
Cloudflare API Token: ********
Cloudflare Zone ID (blank = find automatically):
```

### 3.3 What the wizard does

```
[1] Obtaining IAM token...
[2] Validating DNS zone...
[3] Creating IAM policy...        (dns + elb + scm + cdn permissions)
[4] Creating IAM agency...        (fg-letsencrypt)
[5] Assigning policy to agency...
[6] Creating FunctionGraph function...
[7] Uploading function code...
[8] Adding timer trigger...       (daily at 3 AM)
[9] Saving domain-specific copy...
[10] Invoking function...         (first cert ~60 sec)
```

### 3.4 Resources created

| Resource | Name |
|---|---|
| Function | `letsencrypt-dns-example-com` |
| Timer | `daily-cert-renewal-example-com` |
| Agency | `fg-letsencrypt` (shared) |
| Policy | `letsencrypt-example-com-policy` |
| Script copy | `letsencrypt_dns_example-com.py` |

---

## 4. Installation — HTTP-01

### 4.1 Run the script

```powershell
python setup_letsencrypt_http_fg.py
```

### 4.2 Answer the wizard prompts

```
Huawei Access Key ID (AK): HPUAXXXXXXXXXXXX
Huawei Secret Access Key (SK): ********
Region [tr-west-1]:
Domain: example.com

  Note: HTTP-01 does NOT support wildcard certificates.

Additional domains (SAN, comma-separated, blank for none): www.example.com
Certificate name [letsencrypt-example-com]:
```

### 4.3 Automatic ELB matching

The wizard resolves the domain IP and matches it to an ELB:

```
[2] Resolving domain IP: example.com -> 1.2.3.4
[3] Matching ELB...
    Matched ELB: my-elb (id: xxx)
[4] Finding port 80 HTTP listener...
    Found listener: http-listener (id: cd58...)
[5] Checking L7 policies...
```

> **If you get an error:** The domain IP doesn't match any ELB and the script exits.
> Fix: Make sure the domain's A record points to the ELB's public IP.

### 4.4 What the wizard does

```
[1] Obtaining IAM token...
[2] Resolving domain IP...
[3] Matching ELB...
[4] Finding port 80 HTTP listener...
[5] Checking L7 policies...
[6] Creating IAM policy...        (elb + scm + cdn permissions)
[7] Creating IAM agency...        (fg-letsencrypt)
[8] Assigning policy to agency...
[9] Creating FunctionGraph function...
[10] Uploading function code...
[11] Adding timer trigger...      (daily at 3 AM)
[12] Saving domain-specific copy...
[13] Invoking function...         (first cert ~60 sec)
```

---

## 5. CSV Credentials Auto-Import

Place a `credentials.csv` in the script directory:

```csv
User Name,Access Key Id,Secret Access Key
H00XXXX,HPUAXXXX,XXXXXXXXXXXX
```

The wizard auto-detects the AK/SK. Press Enter to accept.

---

## 6. Multiple Domains

Run the same script again for different domains. Separate resources are created for each — previous domains are not overwritten.

```powershell
# 1st domain
python setup_letsencrypt_fg.py    # -> example.com

# 2nd domain
python setup_letsencrypt_fg.py    # -> test.example.org
```

The agency (`fg-letsencrypt`) is shared across all domains.

---

## 7. Verification

After installation, check the following:

| Step | How |
|---|---|
| Function created? | FunctionGraph console > Functions |
| Timer trigger present? | Function > Triggers > cron `0 0 3 * * ?` |
| First cert issued? | ELB > Certificates > cert matching your domain |
| Cert bound to listener? | ELB > Listeners > HTTPS listener > cert |

The first certificate takes ~60 seconds. If it fails, check the function logs.

---

## 8. Manual Testing (Event Override)

You can manually invoke the function from the FunctionGraph console.

### Force renewal

```json
{
  "force_renew": true
}
```

### New domain test (DNS-01)

```json
{
  "domain": "test.example.com",
  "domains": ["test.example.com"],
  "cert_name": "letsencrypt-test-example-com"
}
```

### New domain test (HTTP-01)

```json
{
  "domain": "test.example.com",
  "domains": ["test.example.com"],
  "http_listener_id": "cd58...",
  "cert_name": "letsencrypt-test-example-com"
}
```

> An empty event `{}` uses the default config (this is what the timer trigger sends).

---

## 9. Troubleshooting

| Problem | Solution |
|---|---|
| `403 Forbidden` | AK/SK lacks IAM admin permissions |
| `DNS zone not found` | Create a public zone for the domain (or check if a parent zone exists) |
| `ELB not found` (HTTP-01) | Point the domain A record to the ELB's public IP |
| `No port 80 HTTP listener` (HTTP-01) | Add an HTTP protocol, port 80 listener to the ELB |
| `enhance_l7policy_enable false` (HTTP-01) | The wizard auto-enables it; if it can't, enable it manually on the listener |
| Certificate failed | Check function logs; Let's Encrypt rate limit is 50 certs/week/domain |
| CCM error | Non-fatal — ELB cert still succeeds. CCM regions: `cn-north-4`, `ap-southeast-1`, `my-kualalumpur-1` |
| CDN error | Non-fatal — skipped if no matching CDN domain exists |

---

## 10. Staging for Testing

Use Let's Encrypt staging instead of production (no rate limit):

Override via event:
```json
{
  "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"
}
```

---

## File Reference

| File | Purpose |
|---|---|
| `setup_letsencrypt_fg.py` | DNS-01 setup wizard (English) |
| `setup_letsencrypt_fg_tr.py` | DNS-01 setup wizard (Turkish) |
| `setup_letsencrypt_http_fg.py` | HTTP-01 setup wizard (English) |
| `setup_letsencrypt_http_fg_tr.py` | HTTP-01 setup wizard (Turkish) |
| `letsencrypt_dns.py` | DNS-01 function code (uploaded by setup) |
| `letsencrypt_http.py` | HTTP-01 function code (uploaded by setup) |
