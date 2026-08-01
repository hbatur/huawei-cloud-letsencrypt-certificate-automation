# -*- coding: utf-8 -*-
"""
FunctionGraph: Let's Encrypt SSL Certificate Automated Management (DNS-01 + Huawei ELB)

Flow:
  1. Is there a certificate matching the domain in ELB? (searches all ELBs, ELB-independent)
  2. If present and valid for >30 days -> skip renewal (rate limit protection)
  3. Obtain a new certificate via Let's Encrypt DNS-01 challenge
  4. Upload to ELB:
     - If present -> update (cert ID unchanged, listeners auto-updated)
     - If absent -> create (only upload to ELB certificates, no listener binding)
  5. Find and report the listeners using this certificate

Dependencies: requests (available in FunctionGraph)
libcrypto (OpenSSL) is loaded via ctypes, no pip package needed
"""

import json
import base64
import hashlib
import time
import os
import ctypes
import ctypes.util
import requests
from datetime import datetime, timezone


# ===========================================================================
# CONFIGURATION  --  edit this section for your own environment
# Can also be overridden via event (timer trigger sends an empty event)
# ===========================================================================

DOMAIN = "example.com"
ZONE_ID = "your-zone-id-here"
ZONE_NAME = "example.com."
DOMAINS = ["example.com", "www.example.com"]
CERT_NAME = "elb-ssl-test"
REGION = "tr-west-1"
PROJECT_ID = "your-project-id-here"

ACME_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_EMAIL = "mailto:admin@example.com"

RENEW_BEFORE_DAYS = 30

IAM_ENDPOINT = "https://iam.myhuaweicloud.com"
DNS_ENDPOINT = "https://dns.myhuaweicloud.com"

DNS_PROVIDER = "huawei"
CLOUDFLARE_API_TOKEN = ""
CLOUDFLARE_ZONE_ID = ""


# ===========================================================================
# Utility  (base64url, DER, PEM)
# ===========================================================================

def b64url(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64url_decode(data):
    if isinstance(data, str):
        data = data.encode('ascii')
    padding = b'=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def der_to_pem(der_data, pem_type):
    b64 = base64.b64encode(der_data).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {pem_type}-----\n" + "\n".join(lines) + f"\n-----END {pem_type}-----\n"


# ===========================================================================
# OpenSSLWrapper  --  ctypes with libcrypto, no pip package needed
# ===========================================================================

class OpenSSLWrapper:
    NID_sha256 = 672

    def __init__(self):
        path = ctypes.util.find_library("crypto")
        if not path:
            raise Exception("libcrypto not found")
        self.lib = ctypes.CDLL(path)
        self._setup()

    def _setup(self):
        lib = self.lib
        lib.RSA_new.restype = ctypes.c_void_p
        lib.RSA_new.argtypes = []
        lib.RSA_free.restype = None
        lib.RSA_free.argtypes = [ctypes.c_void_p]
        lib.BN_new.restype = ctypes.c_void_p
        lib.BN_new.argtypes = []
        lib.BN_free.restype = None
        lib.BN_free.argtypes = [ctypes.c_void_p]
        lib.BN_set_word.restype = ctypes.c_int
        lib.BN_set_word.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        lib.BN_bn2bin.restype = ctypes.c_int
        lib.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.BN_num_bits.restype = ctypes.c_int
        lib.BN_num_bits.argtypes = [ctypes.c_void_p]
        lib.RSA_generate_key_ex.restype = ctypes.c_int
        lib.RSA_generate_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        lib.RSA_get0_n.restype = ctypes.c_void_p
        lib.RSA_get0_n.argtypes = [ctypes.c_void_p]
        lib.RSA_get0_e.restype = ctypes.c_void_p
        lib.RSA_get0_e.argtypes = [ctypes.c_void_p]
        lib.RSA_sign.restype = ctypes.c_int
        lib.RSA_sign.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p]
        lib.i2d_RSAPrivateKey.restype = ctypes.c_int
        lib.i2d_RSAPrivateKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
        lib.i2d_RSAPublicKey.restype = ctypes.c_int
        lib.i2d_RSAPublicKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
        lib.RSA_size.restype = ctypes.c_int
        lib.RSA_size.argtypes = [ctypes.c_void_p]
        lib.X509_REQ_new.restype = ctypes.c_void_p
        lib.X509_REQ_new.argtypes = []
        lib.X509_REQ_free.restype = None
        lib.X509_REQ_free.argtypes = [ctypes.c_void_p]
        lib.X509_NAME_add_entry_by_txt.restype = ctypes.c_int
        lib.X509_NAME_add_entry_by_txt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        lib.X509_REQ_set_subject_name.restype = ctypes.c_int
        lib.X509_REQ_set_subject_name.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.EVP_PKEY_new.restype = ctypes.c_void_p
        lib.EVP_PKEY_new.argtypes = []
        lib.EVP_PKEY_free.restype = None
        lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        lib.EVP_PKEY_set1_RSA.restype = ctypes.c_int
        lib.EVP_PKEY_set1_RSA.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.X509_REQ_set_pubkey.restype = ctypes.c_int
        lib.X509_REQ_set_pubkey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.OPENSSL_sk_new_null.restype = ctypes.c_void_p
        lib.OPENSSL_sk_new_null.argtypes = []
        lib.OPENSSL_sk_push.restype = ctypes.c_int
        lib.OPENSSL_sk_push.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.X509V3_EXT_conf_nid.restype = ctypes.c_void_p
        lib.X509V3_EXT_conf_nid.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
        lib.X509_REQ_add_extensions.restype = ctypes.c_int
        lib.X509_REQ_add_extensions.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.X509_REQ_sign.restype = ctypes.c_int
        lib.X509_REQ_sign.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        lib.i2d_X509_REQ.restype = ctypes.c_int
        lib.i2d_X509_REQ.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
        lib.EVP_sha256.restype = ctypes.c_void_p
        lib.EVP_sha256.argtypes = []
        lib.X509_REQ_get_subject_name.restype = ctypes.c_void_p
        lib.X509_REQ_get_subject_name.argtypes = [ctypes.c_void_p]

    def generate_rsa_key(self, bits=2048):
        rsa = self.lib.RSA_new()
        if not rsa:
            raise Exception("RSA_new failed")
        e = self.lib.BN_new()
        self.lib.BN_set_word(e, 65537)
        ret = self.lib.RSA_generate_key_ex(rsa, bits, e, None)
        self.lib.BN_free(e)
        if ret != 1:
            self.lib.RSA_free(rsa)
            raise Exception("RSA_generate_key_ex failed")
        return rsa

    def get_public_components(self, rsa):
        n_bn = self.lib.RSA_get0_n(rsa)
        e_bn = self.lib.RSA_get0_e(rsa)
        n_len = (self.lib.BN_num_bits(n_bn) + 7) // 8
        e_len = (self.lib.BN_num_bits(e_bn) + 7) // 8
        n_buf = ctypes.create_string_buffer(n_len)
        e_buf = ctypes.create_string_buffer(e_len)
        self.lib.BN_bn2bin(n_bn, n_buf)
        self.lib.BN_bn2bin(e_bn, e_buf)
        n_bytes = n_buf.raw[:n_len]
        e_bytes = e_buf.raw[:e_len]
        return n_bytes, e_bytes

    def sign_sha256(self, rsa, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        hash_val = hashlib.sha256(data).digest()
        sig_size = self.lib.RSA_size(rsa)
        sig_buf = ctypes.create_string_buffer(sig_size)
        sig_len = ctypes.c_uint(0)
        ret = self.lib.RSA_sign(self.NID_sha256, hash_val, len(hash_val), sig_buf, ctypes.byref(sig_len), rsa)
        if ret != 1:
            raise Exception("RSA_sign failed")
        return sig_buf.raw[:sig_len.value]

    def private_key_to_pem(self, rsa):
        der_len = self.lib.i2d_RSAPrivateKey(rsa, None)
        if der_len <= 0:
            raise Exception("i2d_RSAPrivateKey failed")
        buf = ctypes.create_string_buffer(der_len)
        ptr = ctypes.cast(buf, ctypes.c_char_p)
        self.lib.i2d_RSAPrivateKey(rsa, ctypes.byref(ptr))
        der_data = buf.raw[:der_len]
        return der_to_pem(der_data, "RSA PRIVATE KEY")

    def free_rsa(self, rsa):
        self.lib.RSA_free(rsa)

    def generate_csr(self, domain, san_domains, rsa_key):
        NID_subject_alt_name = 85
        MBSTRING_UTF8 = 0x1000
        req = self.lib.X509_REQ_new()
        if not req:
            raise Exception("X509_REQ_new failed")
        pkey = None
        try:
            subject = self.lib.X509_REQ_get_subject_name(req)
            if not subject:
                raise Exception("X509_REQ_get_subject_name failed")
            cn_bytes = domain.encode('utf-8')
            ret = self.lib.X509_NAME_add_entry_by_txt(
                subject, b"CN", MBSTRING_UTF8, cn_bytes, -1, -1, 0
            )
            if ret != 1:
                raise Exception("X509_NAME_add_entry_by_txt failed")

            pkey = self.lib.EVP_PKEY_new()
            if not pkey:
                raise Exception("EVP_PKEY_new failed")
            ret = self.lib.EVP_PKEY_set1_RSA(pkey, rsa_key)
            if ret != 1:
                raise Exception("EVP_PKEY_set1_RSA failed")
            ret = self.lib.X509_REQ_set_pubkey(req, pkey)
            if ret != 1:
                raise Exception("X509_REQ_set_pubkey failed")

            san_str = ",".join(f"DNS:{d}" for d in san_domains)
            san_bytes = san_str.encode('utf-8')
            ext = self.lib.X509V3_EXT_conf_nid(None, None, NID_subject_alt_name, san_bytes)
            if not ext:
                raise Exception("X509V3_EXT_conf_nid failed")
            ext_stack = self.lib.OPENSSL_sk_new_null()
            if not ext_stack:
                raise Exception("OPENSSL_sk_new_null failed")
            self.lib.OPENSSL_sk_push(ext_stack, ext)
            ret = self.lib.X509_REQ_add_extensions(req, ext_stack)
            if ret != 1:
                raise Exception("X509_REQ_add_extensions failed")

            md = self.lib.EVP_sha256()
            ret = self.lib.X509_REQ_sign(req, pkey, md)
            if ret <= 0:
                raise Exception("X509_REQ_sign failed")

            der_len = self.lib.i2d_X509_REQ(req, None)
            if der_len <= 0:
                raise Exception("i2d_X509_REQ failed")
            buf = ctypes.create_string_buffer(der_len)
            ptr = ctypes.cast(buf, ctypes.c_char_p)
            self.lib.i2d_X509_REQ(req, ctypes.byref(ptr))
            return buf.raw[:der_len]
        finally:
            if pkey:
                self.lib.EVP_PKEY_free(pkey)
            self.lib.X509_REQ_free(req)


# ===========================================================================
# DER encoding helpers  (for CSR)
# ===========================================================================

def der_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
    else:
        raise Exception(f"DER length too large: {length}")


def der_sequence(contents):
    return b'\x30' + der_length(len(contents)) + contents


def der_set(contents):
    return b'\x31' + der_length(len(contents)) + contents


def der_integer(value):
    if isinstance(value, int):
        if value == 0:
            return b'\x02\x01\x00'
        length = (value.bit_length() + 8) // 8
        value_bytes = value.to_bytes(length, 'big')
        if value_bytes[0] & 0x80:
            value_bytes = b'\x00' + value_bytes
        return b'\x02' + der_length(len(value_bytes)) + value_bytes
    else:
        if value[0] & 0x80:
            value = b'\x00' + value
        return b'\x02' + der_length(len(value)) + value


def der_oid(oid_str):
    parts = [int(x) for x in oid_str.split('.')]
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 0x80:
            encoded += bytes([part])
        else:
            octets = []
            while part > 0:
                octets.append(part & 0x7f)
                part >>= 7
            for i in range(1, len(octets)):
                octets[i] |= 0x80
            encoded += bytes(reversed(octets))
    return b'\x06' + der_length(len(encoded)) + encoded


def der_bitstring(data):
    return b'\x03' + der_length(len(data) + 1) + b'\x00' + data


def der_utf8string(s):
    encoded = s.encode('utf-8')
    return b'\x0c' + der_length(len(encoded)) + encoded


def der_context(tag, contents):
    return bytes([0xa0 | tag]) + der_length(len(contents)) + contents


def build_csr_der(domain, san_domains, n_bytes, e_bytes, sign_func):
    rsa_encryption_oid = der_oid("1.2.840.113549.1.1.1")
    null_params = b'\x05\x00'
    algorithm_identifier = der_sequence(rsa_encryption_oid + null_params)

    rsa_pubkey_der = der_sequence(der_integer(n_bytes) + der_integer(e_bytes))
    subject_public_key_info = der_sequence(algorithm_identifier + der_bitstring(rsa_pubkey_der))

    cn_oid = der_oid("2.5.4.3")
    cn_attr = der_sequence(cn_oid + der_utf8string(domain))
    subject = der_sequence(der_set(cn_attr))

    san_oid = der_oid("2.5.29.17")
    dns_name_tag = b'\x82'
    san_entries = b''
    for d in san_domains:
        d_encoded = d.encode('utf-8')
        san_entries += dns_name_tag + der_length(len(d_encoded)) + d_encoded
    san_value = der_sequence(san_entries)
    san_extension = der_sequence(san_oid + b'\x04' + der_length(len(san_value)) + san_value)

    ext_req_oid = der_oid("1.2.840.113549.1.9.14")
    ext_req_attr = der_sequence(ext_req_oid + der_set(san_extension))
    attributes = der_context(0, ext_req_attr)

    cri = der_sequence(
        der_integer(0) +
        subject +
        subject_public_key_info +
        attributes
    )

    sig_alg_oid = der_oid("1.2.840.113549.1.1.11")
    sig_algorithm = der_sequence(sig_alg_oid + null_params)

    signature = sign_func(cri)
    signature_bitstring = der_bitstring(signature)

    csr = der_sequence(cri + sig_algorithm + signature_bitstring)
    return csr


# ===========================================================================
# ACMEClient  --  Let's Encrypt RFC 8555
# ===========================================================================

class ACMEClient:
    def __init__(self, directory_url, ssl_wrapper):
        self.directory_url = directory_url
        self.ssl = ssl_wrapper
        self.session = requests.Session()
        self.nonce = None
        self.kid = None
        self.account_rsa = self.ssl.generate_rsa_key(2048)
        self._get_directory()
        self._get_nonce()

    def _get_directory(self):
        resp = self.session.get(self.directory_url)
        resp.raise_for_status()
        self.directory = resp.json()

    def _get_nonce(self):
        resp = self.session.head(self.directory['newNonce'])
        self.nonce = resp.headers['Replay-Nonce']

    def _jwk(self):
        n_bytes, e_bytes = self.ssl.get_public_components(self.account_rsa)
        return {"kty": "RSA", "e": b64url(e_bytes), "n": b64url(n_bytes)}

    def _sign_jws(self, payload, url):
        if payload is None:
            payload_b64 = ""
        else:
            if isinstance(payload, dict):
                payload = json.dumps(payload)
            payload_b64 = b64url(payload)

        protected = {"alg": "RS256", "nonce": self.nonce, "url": url}
        if self.kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = self._jwk()

        protected_b64 = b64url(json.dumps(protected))
        signing_input = (protected_b64 + "." + payload_b64).encode('ascii')
        signature = self.ssl.sign_sha256(self.account_rsa, signing_input)
        signature_b64 = b64url(signature)

        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64
        }
        return json.dumps(jws)

    def _post(self, url, payload=None):
        jws_body = self._sign_jws(payload, url)
        headers = {"Content-Type": "application/jose+json"}
        resp = self.session.post(url, data=jws_body, headers=headers)
        if 'Replay-Nonce' in resp.headers:
            self.nonce = resp.headers['Replay-Nonce']
        return resp

    def register_account(self, contact_emails=None):
        if contact_emails is None:
            contact_emails = ["mailto:admin@example.com"]
        payload = {"termsOfServiceAgreed": True, "contact": contact_emails}
        resp = self._post(self.directory['newAccount'], payload)
        if resp.status_code not in (200, 201):
            raise Exception(f"Account registration failed: {resp.status_code} {resp.text}")
        self.kid = resp.headers['Location']
        return resp.json()

    def create_order(self, domains):
        identifiers = [{"type": "dns", "value": d} for d in domains]
        payload = {"identifiers": identifiers}
        resp = self._post(self.directory['newOrder'], payload)
        if resp.status_code != 201:
            raise Exception(f"Order creation failed: {resp.status_code} {resp.text}")
        order = resp.json()
        order['url'] = resp.headers['Location']
        return order

    def get_authorization(self, auth_url):
        resp = self._post(auth_url, None)
        if resp.status_code != 200:
            raise Exception(f"Get authorization failed: {resp.status_code} {resp.text}")
        return resp.json()

    def get_dns_challenge(self, authorization):
        for challenge in authorization['challenges']:
            if challenge['type'] == 'dns-01':
                return challenge
        raise Exception("No dns-01 challenge found")

    def compute_dns_validation(self, challenge):
        token = challenge['token']
        jwk_json = json.dumps(self._jwk(), sort_keys=True, separators=(',', ':'))
        thumbprint = hashlib.sha256(jwk_json.encode('utf-8')).digest()
        key_authorization = token + "." + b64url(thumbprint)
        validation = hashlib.sha256(key_authorization.encode('utf-8')).digest()
        return b64url(validation), key_authorization

    def answer_challenge(self, challenge_url):
        resp = self._post(challenge_url, {})
        if resp.status_code != 200:
            raise Exception(f"Answer challenge failed: {resp.status_code} {resp.text}")
        return resp.json()

    def poll_authorization(self, auth_url, timeout=120):
        start = time.time()
        while time.time() - start < timeout:
            resp = self._post(auth_url, None)
            if resp.status_code != 200:
                raise Exception(f"Poll auth failed: {resp.status_code} {resp.text}")
            auth = resp.json()
            status = auth['status']
            if status == 'valid':
                return auth
            elif status == 'invalid':
                raise Exception(f"Authorization invalid: {auth}")
            time.sleep(3)
        raise Exception("Authorization timed out")

    def poll_order(self, order_url, timeout=120):
        start = time.time()
        while time.time() - start < timeout:
            resp = self._post(order_url, None)
            if resp.status_code != 200:
                raise Exception(f"Poll order failed: {resp.status_code} {resp.text}")
            order = resp.json()
            status = order['status']
            if status in ('ready', 'valid'):
                return order
            elif status == 'invalid':
                raise Exception(f"Order invalid: {order}")
            time.sleep(3)
        raise Exception("Order timed out")

    def finalize_order(self, finalize_url, domains, cert_rsa):
        csr_der = self.ssl.generate_csr(domains[0], domains, cert_rsa)
        payload = {"csr": b64url(csr_der)}
        resp = self._post(finalize_url, payload)
        if resp.status_code != 200:
            raise Exception(f"Finalize failed: {resp.status_code} {resp.text}")
        return resp.json()

    def download_certificate(self, cert_url):
        resp = self._post(cert_url, None)
        if resp.status_code != 200:
            raise Exception(f"Download cert failed: {resp.status_code} {resp.text}")
        return resp.text


# ===========================================================================
# HuaweiDNSClient  --  DNS-01 TXT record management (REST)
# ===========================================================================

class HuaweiDNSClient:
    def __init__(self, token, zone_id, zone_name):
        self.token = token
        self.zone_id = zone_id
        self.zone_name = zone_name
        self.headers = {
            "X-Auth-Token": token,
            "Content-Type": "application/json"
        }

    def create_txt_record(self, record_name, value, ttl=300):
        url = f"{DNS_ENDPOINT}/v2/zones/{self.zone_id}/recordsets"

        list_resp = requests.get(
            url, params={"name": record_name, "type": "TXT"},
            headers=self.headers, timeout=30
        )
        if list_resp.status_code == 200:
            for rs in list_resp.json().get("recordsets", []):
                if rs.get("name") == record_name:
                    try:
                        self.delete_txt_record(rs["id"])
                        time.sleep(5)
                    except Exception:
                        pass

        body = {
            "name": record_name,
            "type": "TXT",
            "ttl": ttl,
            "records": [f'"{value}"']
        }
        resp = requests.post(url, json=body, headers=self.headers, timeout=30)
        if resp.status_code not in (200, 201, 202):
            raise Exception(f"Create TXT record failed: {resp.status_code} {resp.text}")
        data = resp.json()
        return data['id']

    def delete_txt_record(self, recordset_id):
        url = f"{DNS_ENDPOINT}/v2/zones/{self.zone_id}/recordsets/{recordset_id}"
        resp = requests.delete(url, headers=self.headers, timeout=30)
        if resp.status_code != 204:
            raise Exception(f"Delete TXT record failed: {resp.status_code} {resp.text}")


# ===========================================================================
# CloudflareDNSClient  --  DNS-01 TXT record management (Cloudflare REST API)
# ===========================================================================

class CloudflareDNSClient:
    def __init__(self, api_token, zone_id):
        self.zone_id = zone_id
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

    def create_txt_record(self, record_name, value, ttl=300):
        cf_name = record_name.rstrip('.')
        url = f"{self.base_url}/zones/{self.zone_id}/dns_records"

        list_resp = requests.get(
            url, params={"name": cf_name, "type": "TXT"},
            headers=self.headers, timeout=30
        )
        if list_resp.status_code == 200:
            for rec in list_resp.json().get("result", []):
                if rec.get("name") == cf_name:
                    try:
                        self.delete_txt_record(rec["id"])
                        time.sleep(2)
                    except Exception:
                        pass

        body = {
            "type": "TXT",
            "name": cf_name,
            "content": value,
            "ttl": ttl
        }
        resp = requests.post(url, json=body, headers=self.headers, timeout=30)
        if resp.status_code not in (200, 201):
            raise Exception(f"Cloudflare create TXT record failed: {resp.status_code} {resp.text}")
        data = resp.json()
        return data["result"]["id"]

    def delete_txt_record(self, record_id):
        url = f"{self.base_url}/zones/{self.zone_id}/dns_records/{record_id}"
        resp = requests.delete(url, headers=self.headers, timeout=30)
        if resp.status_code not in (200, 204):
            raise Exception(f"Cloudflare delete TXT record failed: {resp.status_code} {resp.text}")


# ===========================================================================
# HuaweiELBClient  --  ELB v3 REST API (certificate + listener + LB search)
# ===========================================================================

class HuaweiELBClient:
    def __init__(self, token, region, project_id):
        self.endpoint = f"https://elb.{region}.myhuaweicloud.com"
        self.project_id = project_id
        self.headers = {
            "X-Auth-Token": token,
            "Content-Type": "application/json"
        }

    def _url(self, path):
        return f"{self.endpoint}/v3/{self.project_id}/elb/{path}"

    # --- LoadBalancer ---

    def find_loadbalancer_by_name(self, name):
        url = self._url("loadbalancers")
        resp = requests.get(url, headers=self.headers, timeout=30)
        if resp.status_code != 200:
            raise Exception(f"List loadbalancers failed: {resp.status_code} {resp.text}")
        for lb in resp.json().get("loadbalancers", []):
            if lb.get("name") == name:
                return lb
        return None

    # --- Listener ---

    def _list_all_listeners(self):
        url = self._url("listeners")
        resp = requests.get(url, headers=self.headers, timeout=30)
        if resp.status_code != 200:
            raise Exception(f"List listeners failed: {resp.status_code} {resp.text}")
        return resp.json().get("listeners", [])

    def find_listeners_by_cert(self, cert_id):
        listeners = []
        for l in self._list_all_listeners():
            default_ref = l.get("default_tls_container_ref") or ""
            sni_refs = l.get("sni_container_refs") or []
            if default_ref == cert_id or cert_id in sni_refs:
                listeners.append(l)
        return listeners

    def find_all_https_listeners(self):
        listeners = []
        for l in self._list_all_listeners():
            if l.get("protocol") in ("HTTPS", "TERMINATED_HTTPS"):
                listeners.append(l)
        return listeners

    def find_https_listeners(self, loadbalancer_id):
        listeners = []
        for l in self._list_all_listeners():
            lb_ids = [lb.get("id") for lb in (l.get("loadbalancers") or [])]
            if loadbalancer_id in lb_ids and l.get("protocol") in ("HTTPS", "TERMINATED_HTTPS"):
                listeners.append(l)
        return listeners

    def bind_cert_to_listener(self, listener_id, cert_id):
        url = self._url(f"listeners/{listener_id}")
        body = {"listener": {"default_tls_container_ref": cert_id}}
        resp = requests.put(url, json=body, headers=self.headers, timeout=30)
        if resp.status_code not in (200, 202):
            raise Exception(f"Bind cert to listener failed: {resp.status_code} {resp.text}")
        return resp.json()

    # --- Certificate ---

    def _list_certificates(self):
        url = self._url("certificates")
        resp = requests.get(url, headers=self.headers, timeout=30)
        if resp.status_code != 200:
            raise Exception(f"List certificates failed: {resp.status_code} {resp.text}")
        return resp.json().get("certificates", [])

    def find_certificate_by_domain(self, domains):
        target = set(d.strip().lower() for d in domains)
        for cert in self._list_certificates():
            cert_domains = set(
                d.strip().lower() for d in (cert.get("domain") or "").split(",") if d.strip()
            )
            if cert_domains == target:
                return cert
        return None

    def create_certificate(self, name, cert_pem, key_pem, domain_str):
        url = self._url("certificates")
        body = {
            "certificate": {
                "name": name,
                "certificate": cert_pem,
                "private_key": key_pem,
                "type": "server",
                "domain": domain_str
            }
        }
        resp = requests.post(url, json=body, headers=self.headers, timeout=30)
        if resp.status_code not in (200, 201):
            raise Exception(f"ELB create cert failed: {resp.status_code} {resp.text}")
        return resp.json()["certificate"]["id"]

    def update_certificate(self, cert_id, cert_pem, key_pem):
        url = self._url(f"certificates/{cert_id}")
        body = {
            "certificate": {
                "certificate": cert_pem,
                "private_key": key_pem
            }
        }
        resp = requests.put(url, json=body, headers=self.headers, timeout=30)
        if resp.status_code not in (200, 202):
            raise Exception(f"ELB update cert failed: {resp.status_code} {resp.text}")
        return cert_id

    def upsert_certificate(self, name, cert_pem, key_pem, domain_str, domains):
        existing = self.find_certificate_by_domain(domains)
        if existing:
            cert_id = existing["id"]
            self.update_certificate(cert_id, cert_pem, key_pem)
            return cert_id, "updated", existing.get("name", "")
        else:
            cert_id = self.create_certificate(name, cert_pem, key_pem, domain_str)
            return cert_id, "created", name


# ===========================================================================
# IAM helper  --  project_id auto-detect
# ===========================================================================

def get_project_id(token, fallback_project_id=""):
    try:
        resp = requests.get(
            f"{IAM_ENDPOINT}/v3/auth/tokens",
            headers={"X-Auth-Token": token, "X-Subject-Token": token},
            timeout=10
        )
        if resp.status_code == 200:
            project = resp.json().get("token", {}).get("project", {})
            if project.get("id"):
                return project["id"]
    except Exception:
        pass
    if fallback_project_id:
        return fallback_project_id
    raise Exception("Could not determine project_id")


def get_token_from_context(context):
    try:
        return context.getToken()
    except Exception as e:
        raise Exception(
            f"Failed to get token from context: {e}. "
            "Make sure the function has an agency (xrole) configured."
        )


# ===========================================================================
# DNS propagation check  (DoH via dns.google)
# ===========================================================================

def wait_for_dns_propagation(txt_record_name, validation, max_retries=24, interval=5):
    for _ in range(max_retries):
        time.sleep(interval)
        try:
            doh_resp = requests.get(
                "https://dns.google/resolve",
                params={"name": txt_record_name, "type": "TXT"},
                timeout=10
            )
            if doh_resp.status_code == 200:
                answers = doh_resp.json().get("Answer", [])
                for ans in answers:
                    ans_data = ans.get("data", "").strip('"')
                    if ans_data == validation:
                        return True
        except Exception:
            pass
    return False


# ===========================================================================
# Renewal check
# ===========================================================================

def check_cert_needs_renewal(cert_info, renew_before_days):
    if not cert_info:
        return True, None
    expire_str = cert_info.get("expire_time", "")
    if not expire_str:
        return True, None
    try:
        expire_str_clean = expire_str.replace("Z", "+00:00")
        expire_dt = datetime.fromisoformat(expire_str_clean)
        now_utc = datetime.now(timezone.utc)
        days_left = (expire_dt - now_utc).days
        return days_left <= renew_before_days, days_left
    except Exception:
        return True, None


# ===========================================================================
# MAIN HANDLER  --  FunctionGraph entry point
# ===========================================================================

def handler(event, context):
    import traceback

    cfg_domain = DOMAIN
    cfg_zone_id = ZONE_ID
    cfg_zone_name = ZONE_NAME
    cfg_domains = DOMAINS
    cfg_cert_name = CERT_NAME
    cfg_region = REGION
    cfg_project_id = PROJECT_ID
    cfg_acme_url = ACME_DIRECTORY_URL
    cfg_account_email = ACCOUNT_EMAIL
    cfg_renew_before = RENEW_BEFORE_DAYS
    cfg_dns_provider = DNS_PROVIDER
    cfg_cloudflare_api_token = CLOUDFLARE_API_TOKEN
    cfg_cloudflare_zone_id = CLOUDFLARE_ZONE_ID

    if isinstance(event, str):
        try:
            event = json.loads(event)
        except Exception:
            event = {}
    if event is None:
        event = {}

    cfg_domain = event.get("domain", cfg_domain)
    cfg_zone_id = event.get("zone_id", cfg_zone_id)
    cfg_zone_name = event.get("zone_name", cfg_zone_name)
    cfg_domains = event.get("domains", cfg_domains)
    cfg_cert_name = event.get("cert_name", cfg_cert_name)
    cfg_region = event.get("region", cfg_region)
    cfg_project_id = event.get("project_id", cfg_project_id)
    cfg_acme_url = event.get("acme_directory_url", cfg_acme_url)
    cfg_account_email = event.get("account_email", cfg_account_email)
    cfg_renew_before = event.get("renew_before_days", cfg_renew_before)
    cfg_dns_provider = event.get("dns_provider", cfg_dns_provider)
    cfg_cloudflare_api_token = event.get("cloudflare_api_token", cfg_cloudflare_api_token)
    cfg_cloudflare_zone_id = event.get("cloudflare_zone_id", cfg_cloudflare_zone_id)
    force_renew = event.get("force_renew", False)

    cleanup_records = []
    dns_client = None
    elb_client = None
    ssl_wrapper = None
    acme = None

    try:
        token = get_token_from_context(context)
        project_id = get_project_id(token, cfg_project_id)

        elb_client = HuaweiELBClient(token, cfg_region, project_id)

        # --- 1. Find existing certificate by domain (across all ELBs) ---
        existing_cert = elb_client.find_certificate_by_domain(cfg_domains)

        # --- 2. Is renewal needed? ---
        if not force_renew:
            needs_renewal, days_left = check_cert_needs_renewal(
                existing_cert, cfg_renew_before
            )
            if not needs_renewal:
                using_listeners = elb_client.find_listeners_by_cert(existing_cert["id"])
                return {
                    "statusCode": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "status": "skip",
                        "message": f"Certificate for {cfg_domains} is valid for {days_left} more days. Renewal not needed.",
                        "cert_name": existing_cert.get("name", ""),
                        "cert_id": existing_cert.get("id", ""),
                        "domains": cfg_domains,
                        "days_left": days_left,
                        "listeners_using_cert": len(using_listeners)
                    }, indent=2)
                }

        # --- 3. Obtain certificate via Let's Encrypt DNS-01 ---
        ssl_wrapper = OpenSSLWrapper()
        if cfg_dns_provider == "cloudflare":
            dns_client = CloudflareDNSClient(cfg_cloudflare_api_token, cfg_cloudflare_zone_id)
        else:
            dns_client = HuaweiDNSClient(token, cfg_zone_id, cfg_zone_name)

        acme = ACMEClient(cfg_acme_url, ssl_wrapper)
        acme.register_account(contact_emails=[cfg_account_email])

        order = acme.create_order(cfg_domains)

        for auth_url in order['authorizations']:
            auth = acme.get_authorization(auth_url)
            challenge = acme.get_dns_challenge(auth)
            validation, key_auth = acme.compute_dns_validation(challenge)

            domain = auth['identifier']['value']
            # For wildcard domains the TXT record is written to the base domain
            # *.example.com -> _acme-challenge.example.com. (*. prefix is removed)
            txt_domain = domain[2:] if domain.startswith("*.") else domain
            txt_record_name = f"_acme-challenge.{txt_domain}."

            recordset_id = dns_client.create_txt_record(txt_record_name, validation)
            cleanup_records.append(recordset_id)

            if not wait_for_dns_propagation(txt_record_name, validation):
                raise Exception(f"DNS propagation timeout: TXT record for {txt_record_name} did not propagate")
            time.sleep(30)

            acme.answer_challenge(challenge['url'])
            acme.poll_authorization(auth_url)

        order_url = order['url']
        order = acme.poll_order(order_url)

        cert_rsa = ssl_wrapper.generate_rsa_key(2048)
        acme.finalize_order(order['finalize'], cfg_domains, cert_rsa)
        order = acme.poll_order(order_url)

        cert_pem = acme.download_certificate(order['certificate'])
        cert_key_pem = ssl_wrapper.private_key_to_pem(cert_rsa)

        # --- 4. Update or create ELB certificate ---
        domain_str = ",".join(cfg_domains)

        if existing_cert:
            cert_id = existing_cert["id"]
            cert_actual_name = existing_cert.get("name", "")
            elb_client.update_certificate(cert_id, cert_pem, cert_key_pem)
            cert_action = "updated"
        else:
            cert_id = elb_client.create_certificate(
                cfg_cert_name, cert_pem, cert_key_pem, domain_str
            )
            cert_actual_name = cfg_cert_name
            cert_action = "created"

        # --- 5. Report listeners ---
        bound_listeners = []

        if cert_action == "updated":
            # Update: listeners are auto-updated via cert ID reference
            using_listeners = elb_client.find_listeners_by_cert(cert_id)
            for l in using_listeners:
                bound_listeners.append({
                    "id": l["id"],
                    "name": l.get("name", l["id"]),
                    "status": "auto-updated"
                })
        # Create: only upload the certificate, do not bind to listeners

        result = {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "status": "success",
                "message": "Certificate issued and deployed successfully",
                "domain": cfg_domain,
                "domains": cfg_domains,
                "cert_name": cert_actual_name,
                "cert_id": cert_id,
                "cert_action": cert_action,
                "listeners": bound_listeners,
                "project_id": project_id,
                "project_id_source": "auto" if project_id != cfg_project_id else "fallback"
            }, indent=2)
        }
        return result

    except Exception as e:
        error_msg = traceback.format_exc()
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "status": "error",
                "error": str(e),
                "traceback": error_msg
            })
        }
    finally:
        if dns_client:
            for recordset_id in cleanup_records:
                try:
                    dns_client.delete_txt_record(recordset_id)
                except Exception:
                    pass
        if ssl_wrapper and acme:
            try:
                ssl_wrapper.free_rsa(acme.account_rsa)
            except Exception:
                pass
