# -*- coding: utf-8 -*-
"""
Setup of Let's Encrypt + ELB automation on a new Huawei Cloud account.
Works directly with AK/SK, KooCLI is not required.

Asks all parameters in wizard form, comes with default values.
Then performs the following steps automatically:
  1. Obtain IAM token (with AK/SK)
  2. Validate DNS zone and ELB
  3. Create IAM custom policy (DNS + ELB permissions)
  4. Create IAM agency (trust to FunctionGraph)
  5. Assign policy to agency (all-projects)
  6. Create FunctionGraph function (with agency + code)
  7. Upload function code (with config applied, inline base64)
  8. Add timer trigger
  9. Save domain-specific script copy (does not modify the original file)
  10. (Optional) Invoke the function - first certificate issuance

Prerequisites:
  - DNS public zone created (for the domain)
  - ELB + HTTPS listener created
  - letsencrypt_dns.py file in the same directory

Usage:
  python setup_letsencrypt_fg.py
"""

import requests
import json
import base64
import os
import sys
import io
import csv
import zipfile
import getpass
from urllib.parse import quote

IAM = "https://iam.myhuaweicloud.com"
DNS = "https://dns.myhuaweicloud.com"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


# ===========================================================================
# Wizard helper
# ===========================================================================

def ask(prompt, default=None, required=False, secret=False, choices=None):
    suffix = ""
    if choices:
        suffix = f" [{'/'.join(choices)}]"
    if default is not None and not secret:
        suffix = f" [{default}]{suffix}"
    elif default is not None and secret:
        suffix = f" [***]{suffix}"

    while True:
        if secret:
            val = getpass.getpass(f"  {prompt}{suffix}: ")
        else:
            val = input(f"  {prompt}{suffix}: ").strip()

        if not val and default is not None:
            val = default
        if not val and required:
            print("    This field is required, please enter again.")
            continue
        if choices and val not in choices:
            print(f"    Invalid choice. Options: {choices}")
            continue
        if not val and not required:
            return default
        return val


def confirm(prompt, default_yes=True):
    d = "Y/n" if default_yes else "y/N"
    val = input(f"  {prompt} [{d}]: ").strip().lower()
    if not val:
        return default_yes
    return val in ("y", "yes")


def find_csv_credentials(directory):
    """Find a CSV file with AK/SK credentials in the given directory.

    Expected headers: User Name,Access Key Id,Secret Access Key
    Returns (ak, sk, username, filename) or None if not found.
    """
    expected_headers = ["user name", "access key id", "secret access key"]
    for fname in sorted(os.listdir(directory)):
        if not fname.lower().endswith(".csv"):
            continue
        fpath = os.path.join(directory, fname)
        try:
            with open(fpath, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.reader(f)
                try:
                    headers = next(reader)
                except StopIteration:
                    continue
                if [h.strip().lower() for h in headers] != expected_headers:
                    continue
                try:
                    row = next(reader)
                except StopIteration:
                    continue
                if len(row) < 3:
                    continue
                username = row[0].strip()
                ak = row[1].strip()
                sk = row[2].strip()
                if ak and sk:
                    return ak, sk, username, fname
        except Exception:
            continue
    return None


# ===========================================================================
# API helpers
# ===========================================================================

def get_token(ak, sk, region, security_token=None):
    body = {
        "auth": {
            "identity": {
                "methods": ["hw_ak_sk"],
                "hw_ak_sk": {
                    "access": {"key": ak},
                    "secret": {"key": sk},
                },
            },
            "scope": {"project": {"name": region}},
        }
    }
    if security_token:
        body["auth"]["identity"]["hw_ak_sk"]["security_token"] = {"key": security_token}

    resp = requests.post(f"{IAM}/v3/auth/tokens", json=body, timeout=30)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to get IAM token: {resp.status_code} {resp.text}")

    token = resp.headers.get("X-Subject-Token", "")
    info = resp.json()["token"]
    project_id = info["project"]["id"]
    domain_id = info["project"]["domain"]["id"]
    domain_name = info["project"]["domain"]["name"]
    return token, project_id, domain_id, domain_name


def get_domain_token(ak, sk, domain_name, security_token=None):
    body = {
        "auth": {
            "identity": {
                "methods": ["hw_ak_sk"],
                "hw_ak_sk": {
                    "access": {"key": ak},
                    "secret": {"key": sk},
                },
            },
            "scope": {"domain": {"name": domain_name}},
        }
    }
    if security_token:
        body["auth"]["identity"]["hw_ak_sk"]["security_token"] = {"key": security_token}

    resp = requests.post(f"{IAM}/v3/auth/tokens", json=body, timeout=30)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to get domain token: {resp.status_code} {resp.text}")

    return resp.headers.get("X-Subject-Token", "")


def api_get(url, token, params=None):
    resp = requests.get(url, headers={"X-Auth-Token": token}, params=params, timeout=30)
    return resp


def api_post(url, token, body):
    resp = requests.post(
        url,
        headers={"X-Auth-Token": token, "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    return resp


def api_put(url, token, body=None):
    headers = {"X-Auth-Token": token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    resp = requests.put(url, headers=headers, json=body, timeout=30)
    return resp


def step(n, msg):
    print(f"\n[{n}] {msg}")
    print("-" * 60)


# ===========================================================================
# Setup steps
# ===========================================================================

DNS_ACTIONS = [
    "dns:*:*",
]

ELB_ACTIONS = [
    "elb:*:*",
]


def find_dns_zone(token, domain):
    resp = api_get(f"{DNS}/v2/zones", token)
    if resp.status_code != 200:
        return None
    zones = resp.json().get("zones", [])
    # Try exact domain first, then progressively fall back to parent domains
    # e.g. test1.batur.site -> test1.batur.site. then batur.site.
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:]) + "."
        for z in zones:
            if z.get("name") == candidate:
                return z["id"], z["name"]
    return None


def find_cloudflare_zone(api_token, domain):
    headers = {"Authorization": f"Bearer {api_token}"}
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        resp = requests.get(
            f"{CLOUDFLARE_API}/zones",
            params={"name": candidate},
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 200:
            zones = resp.json().get("result", [])
            if zones:
                return zones[0]["id"], zones[0]["name"]
    return None


def list_elbs(token, region, project_id):
    url = f"https://elb.{region}.myhuaweicloud.com/v3/{project_id}/elb/loadbalancers"
    resp = api_get(url, token)
    if resp.status_code != 200:
        return []
    return resp.json().get("loadbalancers", [])


def create_iam_policy(token, policy_name, region):
    body = {
        "role": {
            "display_name": policy_name,
            "description": "DNS + ELB permissions for Let's Encrypt automation",
            "type": "AX",
            "policy": {
                "Version": "1.1",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": DNS_ACTIONS + ELB_ACTIONS,
                    }
                ],
            },
        }
    }
    iam_endpoint = f"https://iam.{region}.myhuaweicloud.com"
    resp = api_post(f"{iam_endpoint}/v3.0/OS-ROLE/roles", token, body)
    if resp.status_code in (200, 201):
        return resp.json()["role"]["id"]
    if "already" in resp.text.lower() or "duplicate" in resp.text.lower():
        return None
    raise RuntimeError(f"Failed to create policy: {resp.status_code} {resp.text}")


def create_iam_agency(token, domain_id, agency_name, description, region):
    body = {
        "agency": {
            "name": agency_name,
            "domain_id": domain_id,
            "trust_domain_name": "op_svc_cff",
            "description": description,
            "duration": "FOREVER",
        }
    }
    iam_endpoint = f"https://iam.{region}.myhuaweicloud.com"
    agency_url = f"{iam_endpoint}/v3.0/OS-AGENCY/agencies"

    resp = api_post(agency_url, token, body)
    if resp.status_code in (200, 201):
        return resp.json()["agency"]["id"]
    if "already" in resp.text.lower() or "duplicate" in resp.text.lower():
        resp2 = api_get(agency_url + f"?domain_id={domain_id}", token)
        if resp2.status_code == 200:
            for a in resp2.json().get("agencies", []):
                if a.get("name") == agency_name:
                    return a["id"]
        return None

    raise RuntimeError(f"Failed to create agency: {resp.status_code} {resp.text}")


def associate_policy_to_agency(token, domain_id, agency_id, role_id, region):
    iam_endpoint = f"https://iam.{region}.myhuaweicloud.com"
    url = f"{iam_endpoint}/v3.0/OS-INHERIT/domains/{domain_id}/agencies/{agency_id}/roles/{role_id}/inherited_to_projects"
    resp = api_put(url, token)
    return resp.status_code in (200, 201, 204)


def create_function(token, region, project_id, func_name, agency_name,
                    runtime, handler, memory_size, timeout, package):
    url = f"https://functiongraph.{region}.myhuaweicloud.com/v2/{project_id}/fgs/functions"
    body = {
        "func_name": func_name,
        "package": package,
        "runtime": runtime,
        "handler": handler,
        "memory_size": memory_size,
        "timeout": timeout,
        "xrole": agency_name,
        "app_xrole": agency_name,
        "code_type": "zip",
        "code_filename": "index.zip",
    }
    resp = api_post(url, token, body)
    if resp.status_code in (200, 201):
        return resp.json().get("func_urn", "")
    if "already" in resp.text.lower():
        return f"urn:fss:{region}:{project_id}:function:{package}:{func_name}"
    raise RuntimeError(f"Failed to create function: {resp.status_code} {resp.text}")


def upload_code(token, region, project_id, func_urn, code_path):
    with open(code_path, "rb") as f:
        code_b64 = base64.b64encode(f.read()).decode("ascii")
    return upload_code_b64(token, region, project_id, func_urn, code_b64)


def upload_code_content(token, region, project_id, func_urn, code_content):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code_content.encode("utf-8"))
    code_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return upload_code_b64(token, region, project_id, func_urn, code_b64)


def upload_code_b64(token, region, project_id, func_urn, code_b64):
    url = f"https://functiongraph.{region}.myhuaweicloud.com/v2/{project_id}/fgs/functions/{quote(func_urn, safe='')}/code"
    body = {
        "code_type": "zip",
        "code_filename": "index.zip",
        "func_code": {"file": code_b64},
    }
    resp = api_put(url, token, body)
    if resp.status_code in (200, 202):
        return resp.json().get("code_size", 0)
    if resp.status_code == 409:
        return 0
    raise RuntimeError(f"Failed to upload code: {resp.status_code} {resp.text}")


def create_timer_trigger(token, region, project_id, func_urn, trigger_name, cron):
    url = f"https://functiongraph.{region}.myhuaweicloud.com/v2/{project_id}/fgs/triggers/{func_urn}"
    body = {
        "trigger_type_code": "TIMER",
        "event_data": {
            "name": trigger_name,
            "schedule": cron,
            "schedule_type": "Cron",
        },
    }
    resp = api_post(url, token, body)
    if resp.status_code in (200, 201):
        return resp.json().get("trigger_id", "")
    if "already" in resp.text.lower():
        return "exists"
    raise RuntimeError(f"Failed to create trigger: {resp.status_code} {resp.text}")


def invoke_function(token, region, project_id, func_urn):
    url = f"https://functiongraph.{region}.myhuaweicloud.com/v2/{project_id}/fgs/functions/{func_urn}/invocations"
    headers = {
        "X-Auth-Token": token,
        "Content-Type": "application/json",
        "X-CFF-Request-Version": "v1",
        "X-Cff-Log-Type": "tail",
    }
    resp = requests.post(url, headers=headers, json={}, timeout=600)
    if resp.status_code == 200:
        return resp.json()
    raise RuntimeError(f"Invoke failed: {resp.status_code} {resp.text}")


def apply_config_to_content(content, config):
    lines = content.split("\n")
    updated = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("DOMAIN = \"") and not stripped.startswith("DOMAINS"):
            updated.append(f'DOMAIN = "{config["domain"]}"')
        elif stripped.startswith("ZONE_ID = \""):
            updated.append(f'ZONE_ID = "{config["zone_id"]}"')
        elif stripped.startswith("ZONE_NAME = \""):
            updated.append(f'ZONE_NAME = "{config["zone_name"]}"')
        elif stripped.startswith("CERT_NAME = \""):
            updated.append(f'CERT_NAME = "{config["cert_name"]}"')
        elif stripped.startswith("REGION = \""):
            updated.append(f'REGION = "{config["region"]}"')
        elif stripped.startswith("PROJECT_ID = \""):
            updated.append(f'PROJECT_ID = "{config["project_id"]}"')
        elif stripped.startswith("ACME_DIRECTORY_URL = \""):
            updated.append(f'ACME_DIRECTORY_URL = "{config["acme_url"]}"')
        elif stripped.startswith("ACCOUNT_EMAIL = \""):
            updated.append(f'ACCOUNT_EMAIL = "{config["account_email"]}"')
        elif stripped.startswith("DOMAINS = "):
            domains_str = ", ".join(f'"{d}"' for d in config["domains"])
            updated.append(f'DOMAINS = [{domains_str}]')
        elif stripped.startswith("RENEW_BEFORE_DAYS = "):
            updated.append(f'RENEW_BEFORE_DAYS = {config["renew_before"]}')
        elif stripped.startswith("DNS_PROVIDER = \""):
            updated.append(f'DNS_PROVIDER = "{config["dns_provider"]}"')
        elif stripped.startswith("CLOUDFLARE_API_TOKEN = \""):
            updated.append(f'CLOUDFLARE_API_TOKEN = "{config["cloudflare_api_token"]}"')
        elif stripped.startswith("CLOUDFLARE_ZONE_ID = \""):
            updated.append(f'CLOUDFLARE_ZONE_ID = "{config["cloudflare_zone_id"]}"')
        else:
            updated.append(line)
    return "\n".join(updated)


# ===========================================================================
# MAIN  --  Wizard + Setup
# ===========================================================================

def main():
    print("=" * 60)
    print("  Let's Encrypt + Huawei ELB Automation Setup")
    print("  Works directly with AK/SK, KooCLI not required")
    print("=" * 60)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, "letsencrypt_dns.py")

    # --- Wizard ---
    print("\n=== Configuration ===\n")

    ak_default = None
    sk_default = None
    csv_creds = find_csv_credentials(script_dir)
    if csv_creds:
        ak_default, sk_default, csv_user, csv_fname = csv_creds
        masked_ak = ak_default[:4] + "..." + ak_default[-4:] if len(ak_default) > 8 else "***"
        print(f"  Credentials found in '{csv_fname}' (user: {csv_user}, AK: {masked_ak})")
        print(f"  Press Enter to accept, or type to override.\n")

    ak = ask("Huawei Access Key ID (AK)", default=ak_default, required=True, secret=(ak_default is not None))
    sk = ask("Huawei Secret Access Key (SK)", default=sk_default, required=True, secret=True)
    security_token = ask("Security Token (if temporary AK/SK, otherwise leave blank)", secret=True)

    if csv_creds and ak == ak_default:
        print(f"  -> Using credentials for user '{csv_user}' from {csv_fname}")
    region = ask("Region", default="tr-west-1")

    domain = ask("Domain", default="example.com")
    use_wildcard = confirm("Wildcard certificate? (*.domain covers all subdomains)")

    all_domains = []
    if use_wildcard:
        all_domains = [f"*.{domain}", domain]
    else:
        all_domains = [domain]

    dns_provider = ask("DNS provider [1=Huawei Cloud DNS / 2=Cloudflare DNS]", default="1", choices=["1", "2"])
    dns_provider_name = "cloudflare" if dns_provider == "2" else "huawei"

    cloudflare_api_token = ""
    cloudflare_zone_id = ""
    zone_id_input = ""

    if dns_provider == "2":
        print("\n  Cloudflare DNS selected. You need a Cloudflare API Token")
        print("  with 'Zone:DNS:Edit' permission for the relevant zone.")
        print("  Create one at: https://dash.cloudflare.com/profile/api-tokens\n")
        cloudflare_api_token = ask("Cloudflare API Token", required=True, secret=True)
        cloudflare_zone_id = ask("Cloudflare Zone ID (blank = find automatically)", default="")
    else:
        zone_id_input = ask("DNS Zone ID (blank = find automatically)", default="")

    domain_slug = domain.replace('.', '-')
    cert_name = ask("Certificate name", default=f"letsencrypt-{domain_slug}")

    account_email = ask("ACME email", default=f"mailto:admin@{domain}")

    agency_name = ask("Agency name", default="fg-letsencrypt")
    func_name = ask("Function name", default=f"letsencrypt-dns-{domain_slug}")
    timer_name = ask("Timer trigger name", default=f"daily-cert-renewal-{domain_slug}")
    timer_cron = ask("Timer cron (daily 3 AM)", default="0 0 3 * * ?")

    acme_choice = ask("Let's Encrypt environment", default="1", choices=["1", "2"])
    if acme_choice == "1":
        acme_url = "https://acme-v02.api.letsencrypt.org/directory"
        acme_label = "Production"
    else:
        acme_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
        acme_label = "Staging"

    renew_before = int(ask("Renewal threshold days", default="30"))
    memory_size = int(ask("Function memory (MB)", default="512"))
    timeout = int(ask("Function timeout (seconds)", default="600"))

    # --- Preview ---
    print("\n=== Preview ===")
    print(f"  Region:        {region}")
    print(f"  Domain:        {all_domains}")
    print(f"  Wildcard:      {'Yes' if use_wildcard else 'No'}")
    print(f"  DNS provider:  {dns_provider_name}")
    print(f"  Certificate:   {cert_name}")
    print(f"  Agency:        {agency_name}")
    print(f"  Function:      {func_name}")
    print(f"  Timer:         {timer_cron}")
    print(f"  ACME:          {acme_label}")
    print(f"  Renew <        {renew_before} days")
    print(f"  Memory:        {memory_size} MB")
    print(f"  Timeout:       {timeout} s")

    if not confirm("\nContinue with these settings?"):
        print("Cancelled.")
        sys.exit(0)

    errors = []

    # --- 1. IAM token ---
    step(1, "Obtaining IAM token (AK/SK)")
    try:
        token, project_id, domain_id, domain_name = get_token(ak, sk, region, security_token or None)
        print(f"  Project token obtained")
        print(f"  Project ID: {project_id}")
        print(f"  Domain ID:  {domain_id}")
        domain_token = get_domain_token(ak, sk, domain_name, security_token or None)
        print(f"  Domain token obtained (for IAM operations)")
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    # --- 2. Validate DNS zone and ELB ---
    step(2, "Validating DNS zone and ELB")

    zone_id = zone_id_input
    zone_name = f"{domain}."
    if dns_provider == "2":
        if not cloudflare_zone_id:
            cf_result = find_cloudflare_zone(cloudflare_api_token, domain)
            if cf_result:
                cloudflare_zone_id, cf_zone_name = cf_result
                print(f"  Cloudflare zone found: {cloudflare_zone_id} (zone: {cf_zone_name})")
            else:
                print(f"  ERROR: Cloudflare zone for '{domain}' (or its parent domain) not found!")
                print(f"  Please create a zone in Cloudflare first or check the API token permissions.")
                sys.exit(1)
        else:
            print(f"  Cloudflare zone ID: {cloudflare_zone_id} (manual)")
        zone_id = cloudflare_zone_id
        zone_name = f"{domain}."
    else:
        if not zone_id:
            zone_result = find_dns_zone(token, domain)
            if zone_result:
                zone_id, zone_name = zone_result
                if zone_name != f"{domain}.":
                    print(f"  DNS zone found: {zone_id} (zone: {zone_name}, domain: {domain})")
                else:
                    print(f"  DNS zone found: {zone_id}")
            else:
                print(f"  ERROR: DNS zone for '{domain}' (or its parent domain) not found!")
                print(f"  Please create a public zone in Huawei DNS first.")
                sys.exit(1)
        else:
            print(f"  DNS zone ID: {zone_id} (manual)")

    lbs = list_elbs(token, region, project_id)
    if lbs:
        print(f"  {len(lbs)} ELB(s) available (certificate is matched by domain when the function runs)")
    else:
        print(f"  No ELB found (certificate is matched by domain when the function runs)")

    # --- 3. IAM Custom Policy ---
    step(3, "Creating IAM custom policy")
    policy_name = f"letsencrypt-{domain.replace('.', '-')}-policy"
    try:
        role_id = create_iam_policy(domain_token, policy_name, region)
        if role_id:
            print(f"  Policy created: {policy_name} (id={role_id})")
        else:
            print(f"  Policy already exists: {policy_name}")
            print(f"  WARNING: Could not get role ID, policy assignment must be done manually")
            errors.append("Policy assignment must be done manually (policy already exists)")
    except Exception as e:
        print(f"  ERROR: {e}")
        errors.append(f"Failed to create policy: {e}")
        role_id = None

    # --- 4. IAM Agency ---
    step(4, f"Creating IAM agency: {agency_name}")
    try:
        agency_id = create_iam_agency(
            domain_token, domain_id, agency_name,
            f"Agency for FunctionGraph to access DNS+ELB for Let's Encrypt ({domain})",
            region
        )
        print(f"  Agency ready: id={agency_id}")
    except Exception as e:
        print(f"  ERROR: {e}")
        errors.append(f"Failed to create agency: {e}")
        agency_id = None

    # --- 5. Policy -> Agency ---
    step(5, "Assigning policy to agency (all-projects)")
    if role_id and agency_id:
        try:
            if associate_policy_to_agency(domain_token, domain_id, agency_id, role_id, region):
                print(f"  Assignment successful")
            else:
                print(f"  WARNING: Assignment failed, must be done manually")
                errors.append("Policy assignment must be done manually")
        except Exception as e:
            print(f"  ERROR: {e}")
            errors.append(f"Policy assignment failed: {e}")
    else:
        print(f"  Skipped (role_id or agency_id missing)")
        if not errors or "Policy assignment" not in str(errors):
            errors.append("Policy assignment must be done manually")

    # --- Prepare config (before upload) ---
    config = {
        "domain": domain,
        "domains": all_domains,
        "zone_id": zone_id,
        "zone_name": zone_name,
        "cert_name": cert_name,
        "region": region,
        "project_id": project_id,
        "acme_url": acme_url,
        "account_email": account_email,
        "renew_before": renew_before,
        "dns_provider": dns_provider_name,
        "cloudflare_api_token": cloudflare_api_token,
        "cloudflare_zone_id": cloudflare_zone_id,
    }

    # Apply config to the script (in memory, do not modify the original file)
    customized_content = None
    if os.path.exists(script_path):
        with open(script_path, "r", encoding="utf-8") as f:
            original_content = f.read()
        customized_content = apply_config_to_content(original_content, config)

    # --- 6. FunctionGraph function ---
    step(6, f"Creating function: {func_name}")

    if not os.path.exists(script_path):
        print(f"  ERROR: {script_path} not found!")
        errors.append("letsencrypt_dns.py not found, code must be uploaded manually")
        func_urn = f"urn:fss:{region}:{project_id}:function:default:{func_name}"
    else:
        try:
            func_urn = create_function(
                token, region, project_id, func_name, agency_name,
                "Python3.10", "index.handler", memory_size, timeout, "default"
            )
            print(f"  Function ready: {func_urn}")
        except Exception as e:
            print(f"  ERROR: {e}")
            errors.append(f"Failed to create function: {e}")
            func_urn = f"urn:fss:{region}:{project_id}:function:default:{func_name}"

    # --- 7. Upload code (with config applied) ---
    step(7, "Uploading function code (with config applied)")
    if customized_content:
        try:
            code_size = upload_code_content(token, region, project_id, func_urn, customized_content)
            if code_size > 0:
                print(f"  Code uploaded: {code_size} bytes")
            else:
                print(f"  Code already up to date (no changes)")
        except Exception as e:
            print(f"  ERROR: {e}")
            errors.append(f"Failed to upload code: {e}")
    else:
        print(f"  Skipped (script file missing)")

    # --- 8. Timer trigger ---
    step(8, f"Adding timer trigger: {timer_name}")
    try:
        trigger_id = create_timer_trigger(
            token, region, project_id, func_urn, timer_name, timer_cron
        )
        if trigger_id == "exists":
            print(f"  Trigger already exists")
        else:
            print(f"  Trigger created: id={trigger_id}")
    except Exception as e:
        print(f"  ERROR: {e}")
        errors.append(f"Failed to create trigger: {e}")

    # --- 9. Save domain-specific copy ---
    step(9, "Saving domain-specific script copy")
    copy_path = os.path.join(script_dir, f"letsencrypt_dns_{domain_slug}.py")
    if customized_content:
        try:
            with open(copy_path, "w", encoding="utf-8") as f:
                f.write(customized_content)
            print(f"  Copy saved: {copy_path}")
            print(f"  (Original letsencrypt_dns.py was not changed)")
        except Exception as e:
            print(f"  WARNING: Could not save copy: {e}")
            print(f"  Please enter the following values manually:")
            for k, v in config.items():
                print(f"    {k} = {v}")
    else:
        print(f"  Script not found, manual config:")
        for k, v in config.items():
            print(f"    {k} = {v}")

    # --- 10. First run ---
    if not errors and confirm("\nRun the function now? (first certificate issuance ~60 seconds)"):
        step(10, "Invoking function")
        try:
            result = invoke_function(token, region, project_id, func_urn)
            body = result.get("body", "{}")
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except Exception:
                    body = {"raw": body}
            status = body.get("status", "unknown")
            print(f"  Status:       {status}")
            if body.get("domains"):
                print(f"  Domains:      {body['domains']}")
            if body.get("cert_action"):
                print(f"  Cert action:  {body['cert_action']}")
            if body.get("cert_id"):
                print(f"  Cert ID:      {body['cert_id']}")
            if body.get("days_left") is not None:
                print(f"  Days left:    {body['days_left']}")
            if body.get("listeners"):
                print(f"  Listeners:    {len(body['listeners'])} updated")
            if body.get("message"):
                print(f"  Message:      {body['message']}")
            if status == "error":
                errors.append(f"Invoke failed: {body.get('error', 'unknown')}")
        except Exception as e:
            print(f"  ERROR: {e}")
            errors.append(f"Invoke failed: {e}")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("  SETUP SUMMARY")
    print("=" * 60)
    print(f"  Region:      {region}")
    print(f"  Project ID:  {project_id}")
    print(f"  Domain ID:   {domain_id}")
    print(f"  Agency:      {agency_name} ({agency_id})")
    print(f"  Function:    {func_name}")
    print(f"  Domain:      {all_domains}")
    print(f"  Wildcard:    {'Yes' if use_wildcard else 'No'}")
    print(f"  DNS:         {dns_provider_name}")
    if dns_provider == "2":
        print(f"  CF Zone ID:  {cloudflare_zone_id}")
    else:
        print(f"  Zone ID:     {zone_id}")
    print(f"  ACME:        {acme_label}")
    print(f"  Timer:       {timer_cron}")

    if errors:
        print(f"\n  WARNINGS ({len(errors)}):")
        for e in errors:
            print(f"    - {e}")
        print(f"\n  These warnings may need to be resolved manually.")
    else:
        print(f"\n  All steps completed successfully!")

    print(f"\n  Test: Invoke {func_name} from the FunctionGraph console.")
    print(f"  or: python -c \"import letsencrypt_dns; print('OK')\"")
    print("=" * 60)


if __name__ == "__main__":
    main()
