# -*- coding: utf-8 -*-
"""
Let's Encrypt + ELB otomasyonunun yeni bir Huawei Cloud hesabinda kurulumu.
Dogrudan AK/SK ile calisir, KooCLI gerekmez.

Tum parametreleri wizard (etkilesimli) formunda sorar, default degerlerle gelir.
Sonra su adimlari otomatik gerceklestirir:
  1. IAM token al (AK/SK ile)
  2. DNS zone ve ELB dogrula
  3. IAM custom policy olustur (DNS + ELB yetkileri)
  4. IAM agency olustur (FunctionGraph'a trust)
  5. Policy'yi agency'ye ata (all-projects)
  6. FunctionGraph function olustur (agency + kod ile)
  7. Function kodu yukle (config uygulanmis, inline base64)
  8. Timer trigger ekle
  9. Domain-specific script kopyasi kaydet (orijinal dosyayi degistirmez)
  10. (Opsiyonel) Function'i invoke et - ilk sertifika alimi

Onkosullar:
  - DNS public zone olusturulmus (domain icin)
  - ELB + HTTPS listener olusturulmus
  - letsencrypt_dns.py ayni dizinde

Kullanim:
  python setup_letsencrypt_fg_tr.py
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
# Wizard yardimcisi
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
            print("    Bu alan zorunludur, lutfen tekrar girin.")
            continue
        if choices and val not in choices:
            print(f"    Gecersiz secim. Secenekler: {choices}")
            continue
        if not val and not required:
            return default
        return val


def confirm(prompt, default_yes=True):
    d = "Y/n" if default_yes else "y/N"
    val = input(f"  {prompt} [{d}]: ").strip().lower()
    if not val:
        return default_yes
    return val in ("y", "yes", "e", "evet")


def find_csv_credentials(directory):
    """Verilen dizinde AK/SK credential iceren CSV dosyasi bulur.

    Beklenen basliklar: User Name,Access Key Id,Secret Access Key
    (ak, sk, kullanici_adi, dosya_adi) doner, bulunamazsa None.
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
# API yardimcilari
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
        raise RuntimeError(f"IAM token alinamadi: {resp.status_code} {resp.text}")

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
        raise RuntimeError(f"Domain token alinamadi: {resp.status_code} {resp.text}")

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
# Kurulum adimlari
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
    # Once tam domain dene, sonra parent domain'lere fallback yap
    # orn: test1.batur.site -> test1.batur.site. sonra batur.site.
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
            "description": "Let's Encrypt otomasyonu icin DNS + ELB yetkileri",
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
    raise RuntimeError(f"Policy olusturulamadi: {resp.status_code} {resp.text}")


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

    raise RuntimeError(f"Agency olusturulamadi: {resp.status_code} {resp.text}")


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
    raise RuntimeError(f"Function olusturulamadi: {resp.status_code} {resp.text}")


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
    raise RuntimeError(f"Kod yuklenemedi: {resp.status_code} {resp.text}")


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
    raise RuntimeError(f"Trigger olusturulamadi: {resp.status_code} {resp.text}")


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
    raise RuntimeError(f"Invoke basarisiz: {resp.status_code} {resp.text}")


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
# MAIN  --  Wizard + Kurulum
# ===========================================================================

def main():
    print("=" * 60)
    print("  Let's Encrypt + Huawei ELB Otomasyon Kurulumu")
    print("  Dogrudan AK/SK ile calisir, KooCLI gerekmez")
    print("=" * 60)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, "letsencrypt_dns.py")

    # --- Wizard ---
    print("\n=== Yapilandirma ===\n")

    ak_default = None
    sk_default = None
    csv_creds = find_csv_credentials(script_dir)
    if csv_creds:
        ak_default, sk_default, csv_user, csv_fname = csv_creds
        masked_ak = ak_default[:4] + "..." + ak_default[-4:] if len(ak_default) > 8 else "***"
        print(f"  '{csv_fname}' dosyasinda credential bulundu (kullanici: {csv_user}, AK: {masked_ak})")
        print(f"  Kabul icin Enter'a basin, veya override icin yazin.\n")

    ak = ask("Huawei Access Key ID (AK)", default=ak_default, required=True, secret=(ak_default is not None))
    sk = ask("Huawei Secret Access Key (SK)", default=sk_default, required=True, secret=True)
    security_token = ask("Security Token (gecici AK/SK ise, yoksa bos birakin)", secret=True)

    if csv_creds and ak == ak_default:
        print(f"  -> '{csv_user}' kullanicisinin credential'lari {csv_fname} dosyasindan kullaniliyor")
    region = ask("Region", default="tr-west-1")

    domain = ask("Domain", default="example.com")
    use_wildcard = confirm("Wildcard sertifika? (*.domain tum subdomain'leri kapsar)")

    all_domains = []
    if use_wildcard:
        all_domains = [f"*.{domain}", domain]
    else:
        all_domains = [domain]

    dns_provider = ask("DNS saglayici [1=Huawei Cloud DNS / 2=Cloudflare DNS]", default="1", choices=["1", "2"])
    dns_provider_name = "cloudflare" if dns_provider == "2" else "huawei"

    cloudflare_api_token = ""
    cloudflare_zone_id = ""
    zone_id_input = ""

    if dns_provider == "2":
        print("\n  Cloudflare DNS secildi. Cloudflare API Token gereklidir")
        print("  (ilgili zone icin 'Zone:DNS:Edit' yetkisi ile).")
        print("  Olustur: https://dash.cloudflare.com/profile/api-tokens\n")
        cloudflare_api_token = ask("Cloudflare API Token", required=True, secret=True)
        cloudflare_zone_id = ask("Cloudflare Zone ID (bos = otomatik bul)", default="")
    else:
        zone_id_input = ask("DNS Zone ID (bos = otomatik bul)", default="")

    domain_slug = domain.replace('.', '-')
    cert_name = ask("Sertifika adi", default=f"letsencrypt-{domain_slug}")

    account_email = ask("ACME e-posta", default=f"mailto:admin@{domain}")

    agency_name = ask("Agency adi", default="fg-letsencrypt")
    func_name = ask("Function adi", default=f"letsencrypt-dns-{domain_slug}")
    timer_name = ask("Timer trigger adi", default=f"daily-cert-renewal-{domain_slug}")
    timer_cron = ask("Timer cron (gunluk 3 AM)", default="0 0 3 * * ?")

    acme_choice = ask("Let's Encrypt ortami", default="1", choices=["1", "2"])
    if acme_choice == "1":
        acme_url = "https://acme-v02.api.letsencrypt.org/directory"
        acme_label = "Production"
    else:
        acme_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
        acme_label = "Staging"

    renew_before = int(ask("Yenileme esigi (gun)", default="30"))
    memory_size = int(ask("Function bellek (MB)", default="512"))
    timeout = int(ask("Function timeout (saniye)", default="600"))

    # --- Onizleme ---
    print("\n=== Onizleme ===")
    print(f"  Region:        {region}")
    print(f"  Domain:        {all_domains}")
    print(f"  Wildcard:      {'Evet' if use_wildcard else 'Hayir'}")
    print(f"  DNS saglayici: {dns_provider_name}")
    print(f"  Sertifika:     {cert_name}")
    print(f"  Agency:        {agency_name}")
    print(f"  Function:      {func_name}")
    print(f"  Timer:         {timer_cron}")
    print(f"  ACME:          {acme_label}")
    print(f"  Yenile <       {renew_before} gun")
    print(f"  Bellek:        {memory_size} MB")
    print(f"  Timeout:       {timeout} sn")

    if not confirm("\nBu ayarlarla devam edilsin mi?"):
        print("Iptal edildi.")
        sys.exit(0)

    errors = []

    # --- 1. IAM token ---
    step(1, "IAM token aliniyor (AK/SK)")
    try:
        token, project_id, domain_id, domain_name = get_token(ak, sk, region, security_token or None)
        print(f"  Project token alindi")
        print(f"  Project ID: {project_id}")
        print(f"  Domain ID:  {domain_id}")
        domain_token = get_domain_token(ak, sk, domain_name, security_token or None)
        print(f"  Domain token alindi (IAM operasyonlari icin)")
    except Exception as e:
        print(f"  HATA: {e}")
        sys.exit(1)

    # --- 2. DNS zone ve ELB dogrula ---
    step(2, "DNS zone ve ELB dogrulaniyor")

    zone_id = zone_id_input
    zone_name = f"{domain}."
    if dns_provider == "2":
        if not cloudflare_zone_id:
            cf_result = find_cloudflare_zone(cloudflare_api_token, domain)
            if cf_result:
                cloudflare_zone_id, cf_zone_name = cf_result
                print(f"  Cloudflare zone bulundu: {cloudflare_zone_id} (zone: {cf_zone_name})")
            else:
                print(f"  HATA: '{domain}' (veya parent domain) icin Cloudflare zone bulunamadi!")
                print(f"  Once Cloudflare'da bir zone olusturun veya API token yetkilerini kontrol edin.")
                sys.exit(1)
        else:
            print(f"  Cloudflare zone ID: {cloudflare_zone_id} (manuel)")
        zone_id = cloudflare_zone_id
        zone_name = f"{domain}."
    else:
        if not zone_id:
            zone_result = find_dns_zone(token, domain)
            if zone_result:
                zone_id, zone_name = zone_result
                if zone_name != f"{domain}.":
                    print(f"  DNS zone bulundu: {zone_id} (zone: {zone_name}, domain: {domain})")
                else:
                    print(f"  DNS zone bulundu: {zone_id}")
            else:
                print(f"  HATA: '{domain}' (veya parent domain) icin DNS zone bulunamadi!")
                print(f"  Once Huawei DNS'te bir public zone olusturun.")
                sys.exit(1)
        else:
            print(f"  DNS zone ID: {zone_id} (manuel)")

    lbs = list_elbs(token, region, project_id)
    if lbs:
        print(f"  {len(lbs)} ELB mevcut (sertifika function calistiginda domain ile eslesir)")
    else:
        print(f"  ELB bulunamadi (sertifika function calistiginda domain ile eslesir)")

    # --- 3. IAM Custom Policy ---
    step(3, "IAM custom policy olusturuluyor")
    policy_name = f"letsencrypt-{domain.replace('.', '-')}-policy"
    try:
        role_id = create_iam_policy(domain_token, policy_name, region)
        if role_id:
            print(f"  Policy olusturuldu: {policy_name} (id={role_id})")
        else:
            print(f"  Policy zaten mevcut: {policy_name}")
            print(f"  UYARI: Role ID alinamadi, policy atamasi manuel yapilmali")
            errors.append("Policy atamasi manuel yapilmali (policy zaten mevcut)")
    except Exception as e:
        print(f"  HATA: {e}")
        errors.append(f"Policy olusturulamadi: {e}")
        role_id = None

    # --- 4. IAM Agency ---
    step(4, f"IAM agency olusturuluyor: {agency_name}")
    try:
        agency_id = create_iam_agency(
            domain_token, domain_id, agency_name,
            f"FunctionGraph'un DNS+ELB'ye erisimi icin agency - Let's Encrypt ({domain})",
            region
        )
        print(f"  Agency hazir: id={agency_id}")
    except Exception as e:
        print(f"  HATA: {e}")
        errors.append(f"Agency olusturulamadi: {e}")
        agency_id = None

    # --- 5. Policy -> Agency ---
    step(5, "Policy agency'ye ataniyor (all-projects)")
    if role_id and agency_id:
        try:
            if associate_policy_to_agency(domain_token, domain_id, agency_id, role_id, region):
                print(f"  Atama basarili")
            else:
                print(f"  UYARI: Atama basarisiz, manuel yapilmali")
                errors.append("Policy atamasi manuel yapilmali")
        except Exception as e:
            print(f"  HATA: {e}")
            errors.append(f"Policy atamasi basarisiz: {e}")
    else:
        print(f"  Atlandi (role_id veya agency_id eksik)")
        if not errors or "Policy atamasi" not in str(errors):
            errors.append("Policy atamasi manuel yapilmali")

    # --- Config hazirla (upload oncesi) ---
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

    # Config'i script'e uygula (memory'de, orijinal dosyayi degistirme)
    customized_content = None
    if os.path.exists(script_path):
        with open(script_path, "r", encoding="utf-8") as f:
            original_content = f.read()
        customized_content = apply_config_to_content(original_content, config)

    # --- 6. FunctionGraph function ---
    step(6, f"Function olusturuluyor: {func_name}")

    if not os.path.exists(script_path):
        print(f"  HATA: {script_path} bulunamadi!")
        errors.append("letsencrypt_dns.py bulunamadi, kod manuel yuklenmeli")
        func_urn = f"urn:fss:{region}:{project_id}:function:default:{func_name}"
    else:
        try:
            func_urn = create_function(
                token, region, project_id, func_name, agency_name,
                "Python3.10", "index.handler", memory_size, timeout, "default"
            )
            print(f"  Function hazir: {func_urn}")
        except Exception as e:
            print(f"  HATA: {e}")
            errors.append(f"Function olusturulamadi: {e}")
            func_urn = f"urn:fss:{region}:{project_id}:function:default:{func_name}"

    # --- 7. Kod yukle (config uygulanmis) ---
    step(7, "Function kodu yukleniyor (config uygulanmis)")
    if customized_content:
        try:
            code_size = upload_code_content(token, region, project_id, func_urn, customized_content)
            if code_size > 0:
                print(f"  Kod yuklendi: {code_size} byte")
            else:
                print(f"  Kod zaten guncel (degisiklik yok)")
        except Exception as e:
            print(f"  HATA: {e}")
            errors.append(f"Kod yuklenemedi: {e}")
    else:
        print(f"  Atlandi (script dosyasi eksik)")

    # --- 8. Timer trigger ---
    step(8, f"Timer trigger ekleniyor: {timer_name}")
    try:
        trigger_id = create_timer_trigger(
            token, region, project_id, func_urn, timer_name, timer_cron
        )
        if trigger_id == "exists":
            print(f"  Trigger zaten mevcut")
        else:
            print(f"  Trigger olusturuldu: id={trigger_id}")
    except Exception as e:
        print(f"  HATA: {e}")
        errors.append(f"Trigger olusturulamadi: {e}")

    # --- 9. Domain-specific kopya kaydet ---
    step(9, "Domain-specific script kopyasi kaydediliyor")
    copy_path = os.path.join(script_dir, f"letsencrypt_dns_{domain_slug}.py")
    if customized_content:
        try:
            with open(copy_path, "w", encoding="utf-8") as f:
                f.write(customized_content)
            print(f"  Kopya kaydedildi: {copy_path}")
            print(f"  (Orijinal letsencrypt_dns.py degistirilmedi)")
        except Exception as e:
            print(f"  UYARI: Kopya kaydedilemedi: {e}")
            print(f"  Lutfen su degerleri manuel girin:")
            for k, v in config.items():
                print(f"    {k} = {v}")
    else:
        print(f"  Script bulunamadi, manuel config:")
        for k, v in config.items():
            print(f"    {k} = {v}")

    # --- 10. Ilk calisma ---
    if not errors and confirm("\nFunction simdi calistirilsin mi? (ilk sertifika alimi ~60 saniye)"):
        step(10, "Function invoke ediliyor")
        try:
            result = invoke_function(token, region, project_id, func_urn)
            body = result.get("body", "{}")
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except Exception:
                    body = {"raw": body}
            status = body.get("status", "bilinmiyor")
            print(f"  Durum:        {status}")
            if body.get("domains"):
                print(f"  Domain'ler:   {body['domains']}")
            if body.get("cert_action"):
                print(f"  Cert islemi:  {body['cert_action']}")
            if body.get("cert_id"):
                print(f"  Cert ID:      {body['cert_id']}")
            if body.get("days_left") is not None:
                print(f"  Kalan gun:    {body['days_left']}")
            if body.get("listeners"):
                print(f"  Listener'lar: {len(body['listeners'])} guncellendi")
            if body.get("message"):
                print(f"  Mesaj:        {body['message']}")
            if status == "error":
                errors.append(f"Invoke basarisiz: {body.get('error', 'bilinmiyor')}")
        except Exception as e:
            print(f"  HATA: {e}")
            errors.append(f"Invoke basarisiz: {e}")

    # --- Ozet ---
    print("\n" + "=" * 60)
    print("  KURULUM OZETI")
    print("=" * 60)
    print(f"  Region:      {region}")
    print(f"  Project ID:  {project_id}")
    print(f"  Domain ID:   {domain_id}")
    print(f"  Agency:      {agency_name} ({agency_id})")
    print(f"  Function:    {func_name}")
    print(f"  Domain:      {all_domains}")
    print(f"  Wildcard:    {'Evet' if use_wildcard else 'Hayir'}")
    print(f"  DNS:         {dns_provider_name}")
    if dns_provider == "2":
        print(f"  CF Zone ID:  {cloudflare_zone_id}")
    else:
        print(f"  Zone ID:     {zone_id}")
    print(f"  ACME:        {acme_label}")
    print(f"  Timer:       {timer_cron}")

    if errors:
        print(f"\n  UYARILAR ({len(errors)}):")
        for e in errors:
            print(f"    - {e}")
        print(f"\n  Bu uyarilarin manuel cozulmesi gerekebilir.")
    else:
        print(f"\n  Tum adimlar basariyla tamamlandi!")

    print(f"\n  Test: {func_name} function'ini FunctionGraph konsolundan invoke edin.")
    print(f"  veya: python -c \"import letsencrypt_dns; print('OK')\"")
    print("=" * 60)


if __name__ == "__main__":
    main()
