# -*- coding: utf-8 -*-
"""
Setup of Let's Encrypt + ELB automation via HTTP-01 challenge on Huawei Cloud.
Works directly with AK/SK, KooCLI is not required.

HTTP-01 challenge works by serving the challenge response on port 80 via an
ELB L7 policy (FIXED_RESPONSE). No DNS provider is needed.

Prerequisites:
  - Domain's public IP must point to a Huawei ELB (VIP address)
  - The ELB must have an HTTP listener on port 80
  - ELB + HTTPS listener created (for the certificate to be used)

Asks all parameters in wizard form, then performs the following steps:
  1. Obtain IAM token (with AK/SK)
  2. Ask domain
  3. Resolve domain IP and find matching ELB
  4. If no ELB matches -> exit (HTTP-01 won't work)
  5. Find port 80 HTTP listener on the ELB
     - If no HTTP listener on port 80 -> exit
     - Check for existing L7 policies (advanced routing)
  6. Create IAM custom policy (ELB permissions only)
  7. Create IAM agency (trust to FunctionGraph)
  8. Assign policy to agency (all-projects)
  9. Create FunctionGraph function (with agency + code)
  10. Upload function code (with config applied, inline base64)
  11. Add timer trigger
  12. Save domain-specific script copy
  13. (Optional) Invoke the function - first certificate issuance

Usage:
  python setup_letsencrypt_http_fg.py
"""

import requests
import json
import base64
import os
import sys
import io
import csv
import zipfile
import socket
import getpass
from urllib.parse import quote

IAM = "https://iam.myhuaweicloud.com"


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

ELB_ACTIONS = [
    "elb:*:*",
]

SCM_ACTIONS = [
    "scm:*:*",
]

CDN_ACTIONS = [
    "cdn:*:*",
]


def resolve_domain_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None


def list_elbs(token, region, project_id):
    url = f"https://elb.{region}.myhuaweicloud.com/v3/{project_id}/elb/loadbalancers"
    resp = api_get(url, token)
    if resp.status_code != 200:
        return []
    return resp.json().get("loadbalancers", [])


def find_elb_by_ip(lbs, domain_ip):
    for lb in lbs:
        if lb.get("vip_address") == domain_ip:
            return lb
        for pub in lb.get("publicips", []):
            if pub.get("publicip_address") == domain_ip:
                return lb
    return None


def list_listeners(token, region, project_id):
    url = f"https://elb.{region}.myhuaweicloud.com/v3/{project_id}/elb/listeners"
    resp = api_get(url, token)
    if resp.status_code != 200:
        return []
    return resp.json().get("listeners", [])


def find_http_listener_80(listeners, elb_id):
    for l in listeners:
        lb_ids = [lb.get("id") for lb in (l.get("loadbalancers") or [])]
        if elb_id in lb_ids and l.get("protocol_port") == 80:
            return l
    return None


def list_l7_policies(token, region, project_id, listener_id):
    url = f"https://elb.{region}.myhuaweicloud.com/v3/{project_id}/elb/l7policies"
    resp = api_get(url, token, params={"listener_id": listener_id})
    if resp.status_code != 200:
        return []
    return resp.json().get("l7policies", [])


def create_iam_policy(token, policy_name, region):
    actions = ELB_ACTIONS + SCM_ACTIONS + CDN_ACTIONS
    body = {
        "role": {
            "display_name": policy_name,
            "description": "ELB + CCM + CDN permissions for Let's Encrypt HTTP-01 automation",
            "type": "AX",
            "policy": {
                "Version": "1.1",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions,
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
        # Policy already exists - update it to include CCM (scm:*:*) and CDN (cdn:*:*) permissions
        list_resp = api_get(f"{iam_endpoint}/v3.0/OS-ROLE/roles", token)
        if list_resp.status_code == 200:
            for role in list_resp.json().get("roles", []):
                if role.get("display_name") == policy_name:
                    role_id = role["id"]
                    patch_body = {
                        "role": {
                            "display_name": policy_name,
                            "description": body["role"]["description"],
                            "policy": body["role"]["policy"],
                        }
                    }
                    patch_resp = requests.patch(
                        f"{iam_endpoint}/v3.0/OS-ROLE/roles/{role_id}",
                        headers={"X-Auth-Token": token, "Content-Type": "application/json"},
                        json=patch_body, timeout=30,
                    )
                    if patch_resp.status_code in (200, 204):
                        return role_id
                    break
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
        elif stripped.startswith("CERT_NAME = \""):
            updated.append(f'CERT_NAME = "{config["cert_name"]}"')
        elif stripped.startswith("REGION = \""):
            updated.append(f'REGION = "{config["region"]}"')
        elif stripped.startswith("PROJECT_ID = \""):
            updated.append(f'PROJECT_ID = "{config["project_id"]}"')
        elif stripped.startswith("HTTP_LISTENER_ID = \""):
            updated.append(f'HTTP_LISTENER_ID = "{config["http_listener_id"]}"')
        elif stripped.startswith("ACME_DIRECTORY_URL = \""):
            updated.append(f'ACME_DIRECTORY_URL = "{config["acme_url"]}"')
        elif stripped.startswith("ACCOUNT_EMAIL = \""):
            updated.append(f'ACCOUNT_EMAIL = "{config["account_email"]}"')
        elif stripped.startswith("DOMAINS = "):
            domains_str = ", ".join(f'"{d}"' for d in config["domains"])
            updated.append(f'DOMAINS = [{domains_str}]')
        elif stripped.startswith("RENEW_BEFORE_DAYS = "):
            updated.append(f'RENEW_BEFORE_DAYS = {config["renew_before"]}')
        else:
            updated.append(line)
    return "\n".join(updated)


# ===========================================================================
# MAIN  --  Wizard + Setup
# ===========================================================================

def main():
    print("=" * 60)
    print("  Let's Encrypt + Huawei ELB Automation Setup (HTTP-01)")
    print("  Works directly with AK/SK, KooCLI not required")
    print("  No DNS provider needed - challenge served via ELB L7 policy")
    print("=" * 60)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, "letsencrypt_http.py")

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

    print("\n  Note: HTTP-01 challenge does NOT support wildcard certificates.")
    print("  Each domain must resolve to the ELB's public IP.\n")

    extra_domains_str = ask("Additional domains (SAN, comma-separated, blank for none)", default="")
    all_domains = [domain]
    if extra_domains_str:
        for d in extra_domains_str.split(","):
            d = d.strip()
            if d and d not in all_domains:
                all_domains.append(d)

    domain_slug = domain.replace('.', '-')
    cert_name = ask("Certificate name", default=f"letsencrypt-{domain_slug}")

    account_email = ask("ACME email", default=f"mailto:admin@{domain}")

    agency_name = ask("Agency name", default="fg-letsencrypt")
    func_name = ask("Function name", default=f"letsencrypt-http-{domain_slug}")
    timer_name = ask("Timer trigger name", default=f"daily-cert-renewal-http-{domain_slug}")
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
    print(f"  Certificate:   {cert_name}")
    print(f"  Agency:        {agency_name}")
    print(f"  Function:      {func_name}")
    print(f"  Timer:         {timer_cron}")
    print(f"  ACME:          {acme_label}")
    print(f"  Renew <        {renew_before} days")
    print(f"  Memory:        {memory_size} MB")
    print(f"  Timeout:       {timeout} s")
    print(f"  Challenge:     HTTP-01 (via ELB L7 policy)")

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

    # --- 2. Resolve domain IP ---
    step(2, f"Resolving domain IP: {domain}")
    domain_ip = resolve_domain_ip(domain)
    if not domain_ip:
        print(f"  ERROR: Could not resolve domain '{domain}' to an IP address.")
        print(f"  Make sure the domain has a DNS A record pointing to your ELB.")
        sys.exit(1)
    print(f"  {domain} -> {domain_ip}")

    # --- 3. Find matching ELB ---
    step(3, "Finding ELB matching the domain IP")
    lbs = list_elbs(token, region, project_id)
    if not lbs:
        print(f"  ERROR: No ELB found in project {project_id}.")
        print(f"  HTTP-01 challenge requires the domain to point to an ELB.")
        sys.exit(1)

    print(f"  {len(lbs)} ELB(s) found:")
    for lb in lbs:
        vip = lb.get("vip_address", "?")
        pubs = [p.get("publicip_address", "") for p in lb.get("publicips", [])]
        pub_str = f", publicips: {pubs}" if pubs else ""
        print(f"    - {lb.get('name', '?')} (vip: {vip}{pub_str})")

    matched_elb = find_elb_by_ip(lbs, domain_ip)
    if not matched_elb:
        print(f"\n  ERROR: Domain '{domain}' ({domain_ip}) does not match any ELB.")
        print(f"  HTTP-01 challenge will NOT work because Let's Encrypt cannot reach")
        print(f"  the challenge endpoint via http://{domain}/.well-known/acme-challenge/")
        print(f"\n  Make sure the domain's DNS A record points to one of the ELB public IPs above.")
        sys.exit(1)

    print(f"\n  Matched ELB: {matched_elb.get('name', '?')} (id: {matched_elb['id']})")

    # --- 4. Find port 80 HTTP listener ---
    step(4, "Finding port 80 HTTP listener on the matched ELB")
    all_listeners = list_listeners(token, region, project_id)
    http_listener = find_http_listener_80(all_listeners, matched_elb["id"])

    if not http_listener:
        print(f"  ERROR: No listener on port 80 found for ELB '{matched_elb.get('name')}'.")
        print(f"  HTTP-01 challenge requires an HTTP listener on port 80.")
        print(f"\n  Create an HTTP (not TCP) listener on port 80 for this ELB and re-run.")
        sys.exit(1)

    listener_protocol = http_listener.get("protocol", "?")
    listener_id = http_listener["id"]
    listener_name = http_listener.get("name", listener_id)
    print(f"  Found listener: {listener_name} (id: {listener_id})")
    print(f"  Protocol: {listener_protocol}, Port: 80")

    # Check enhance_l7policy_enable (required for FIXED_RESPONSE)
    enhance_l7 = http_listener.get("enhance_l7policy_enable", False)
    if not enhance_l7:
        print(f"\n  WARNING: enhance_l7policy_enable is false on this listener.")
        print(f"  FIXED_RESPONSE policies require enhance_l7policy_enable=true.")
        try:
            update_url = f"https://elb.{region}.myhuaweicloud.com/v3/{project_id}/elb/listeners/{listener_id}"
            resp = requests.put(update_url, json={"listener": {"enhance_l7policy_enable": True}},
                                headers={"X-Auth-Token": token, "Content-Type": "application/json"},
                                timeout=30)
            if resp.status_code in (200, 201):
                print(f"  Successfully enabled enhance_l7policy_enable.")
            else:
                print(f"  Failed to enable: {resp.status_code} {resp.text[:200]}")
                print(f"  Enable it manually in the ELB console and re-run.")
                sys.exit(1)
        except Exception as e:
            print(f"  Error: {e}")
            sys.exit(1)

    if listener_protocol not in ("HTTP",):
        print(f"\n  ERROR: The port 80 listener protocol is '{listener_protocol}', not 'HTTP'.")
        print(f"  L7 policies (FIXED_RESPONSE) only work on HTTP/HTTPS listeners.")
        print(f"  Change the listener protocol to HTTP and re-run.")
        sys.exit(1)

    # --- 5. Check existing L7 policies (advanced routing) ---
    step(5, "Checking existing L7 policies on the HTTP listener")
    existing_policies = list_l7_policies(token, region, project_id, listener_id)
    if existing_policies:
        print(f"  {len(existing_policies)} existing L7 policy/policies found:")
        for p in existing_policies:
            print(f"    - {p.get('name', '?')} (action: {p.get('action', '?')}, priority: {p.get('priority', '?')})")
        print(f"\n  The function will temporarily shift existing policies +100,")
        print(f"  create challenge policies at priority 1, and restore after.")
    else:
        print(f"  No existing L7 policies found. L7 routing is ready.")
        print(f"  The function will create temporary L7 policies for the challenge")
        print(f"  and delete them after the certificate is issued (cleanup).")

    # --- 6. IAM Custom Policy ---
    step(6, "Creating IAM custom policy (ELB only)")
    policy_name = f"letsencrypt-http-{domain.replace('.', '-')}-policy"
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

    # --- 7. IAM Agency ---
    step(7, f"Creating IAM agency: {agency_name}")
    try:
        agency_id = create_iam_agency(
            domain_token, domain_id, agency_name,
            f"Agency for FunctionGraph to access ELB for Let's Encrypt HTTP-01 ({domain})",
            region
        )
        print(f"  Agency ready: id={agency_id}")
    except Exception as e:
        print(f"  ERROR: {e}")
        errors.append(f"Failed to create agency: {e}")
        agency_id = None

    # --- 8. Policy -> Agency ---
    step(8, "Assigning policy to agency (all-projects)")
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
        "cert_name": cert_name,
        "region": region,
        "project_id": project_id,
        "http_listener_id": listener_id,
        "acme_url": acme_url,
        "account_email": account_email,
        "renew_before": renew_before,
    }

    # Apply config to the script (in memory, do not modify the original file)
    customized_content = None
    if os.path.exists(script_path):
        with open(script_path, "r", encoding="utf-8") as f:
            original_content = f.read()
        customized_content = apply_config_to_content(original_content, config)
    else:
        print(f"\n  ERROR: {script_path} not found!")
        sys.exit(1)

    # --- 9. FunctionGraph function ---
    step(9, f"Creating function: {func_name}")
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

    # --- 10. Upload code (with config applied) ---
    step(10, "Uploading function code (with config applied)")
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

    # --- 11. Timer trigger ---
    step(11, f"Adding timer trigger: {timer_name}")
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

    # --- 12. Save domain-specific copy ---
    step(12, "Saving domain-specific script copy")
    copy_path = os.path.join(script_dir, f"letsencrypt_http_{domain_slug}.py")
    if customized_content:
        try:
            with open(copy_path, "w", encoding="utf-8") as f:
                f.write(customized_content)
            print(f"  Copy saved: {copy_path}")
            print(f"  (Original letsencrypt_http.py was not changed)")
        except Exception as e:
            print(f"  WARNING: Could not save copy: {e}")
            print(f"  Please enter the following values manually:")
            for k, v in config.items():
                print(f"    {k} = {v}")
    else:
        print(f"  Script not found, manual config:")
        for k, v in config.items():
            print(f"    {k} = {v}")

    # --- 13. First run ---
    if not errors and confirm("\nRun the function now? (first certificate issuance ~60 seconds)"):
        step(13, "Invoking function")
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
    print(f"  Region:        {region}")
    print(f"  Project ID:    {project_id}")
    print(f"  Domain ID:     {domain_id}")
    print(f"  Agency:        {agency_name} ({agency_id})")
    print(f"  Function:      {func_name}")
    print(f"  Domain:        {all_domains}")
    print(f"  Domain IP:     {domain_ip}")
    print(f"  ELB:           {matched_elb.get('name', '?')} ({matched_elb['id']})")
    print(f"  HTTP Listener: {listener_name} ({listener_id})")
    print(f"  ACME:          {acme_label}")
    print(f"  Timer:         {timer_cron}")
    print(f"  Challenge:     HTTP-01")

    if errors:
        print(f"\n  WARNINGS ({len(errors)}):")
        for e in errors:
            print(f"    - {e}")
        print(f"\n  These warnings may need to be resolved manually.")
    else:
        print(f"\n  All steps completed successfully!")

    print(f"\n  Test: Invoke {func_name} from the FunctionGraph console.")
    print(f"  or: python -c \"import letsencrypt_http; print('OK')\"")
    print("=" * 60)


if __name__ == "__main__":
    main()
