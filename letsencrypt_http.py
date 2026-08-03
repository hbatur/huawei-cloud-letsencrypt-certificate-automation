# -*- coding: utf-8 -*-
"""
FunctionGraph: Let's Encrypt SSL Certificate Automated Management (HTTP-01 + Huawei ELB)

Flow:
  1. Is there a certificate matching the domain in ELB? (searches all ELBs, ELB-independent)
  2. If present and valid for >30 days -> skip renewal (rate limit protection)
  3. Obtain a new certificate via Let's Encrypt HTTP-01 challenge
     - For each domain, create an L7 policy (FIXED_RESPONSE) on the HTTP listener
       that returns the key authorization for the challenge path
     - Let's Encrypt validates by requesting http://<domain>/.well-known/acme-challenge/<token>
     - The L7 policy intercepts this request and returns the fixed response
  4. Upload to ELB:
     - If present -> update (cert ID unchanged, listeners auto-updated)
     - If absent -> create (only upload to ELB certificates, no listener binding)
  5. Find and report the listeners using this certificate
  6. Cleanup: delete all L7 policies created for the challenge

Dependencies: requests (available in FunctionGraph)
libcrypto (OpenSSL) is loaded via ctypes, no pip package needed

Note: HTTP-01 challenge does NOT support wildcard certificates.
      Each domain must resolve to the ELB's public IP and the ELB must have
      an HTTP listener on port 80.
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
DOMAINS = ["example.com"]
CERT_NAME = "letsencrypt-example-com"
REGION = "tr-west-1"
PROJECT_ID = "your-project-id-here"
HTTP_LISTENER_ID = "your-http-listener-id-here"

ACME_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_EMAIL = "mailto:admin@example.com"

RENEW_BEFORE_DAYS = 30

IAM_ENDPOINT = "https://iam.myhuaweicloud.com"

# CCM (Cloud Certificate Manager) - also save the certificate as a hosted cert
# in CCM so it can be downloaded or used by other Huawei Cloud services.
# CCM has no update API; on renewal the existing hosted cert is deleted and re-imported.
# CCM is only available in certain regions (cn-north-4, ap-southeast-1, my-kualalumpur-1).
CCM_ENABLED = True
CCM_CERT_NAME = ""
CCM_REGION = "ap-southeast-1"

# CDN (Content Delivery Network) - also deploy the certificate to CDN domains.
# The CDN API is global (cdn.myhuaweicloud.com), available in cn-north-1 and ap-southeast-1.
# The certificate is deployed to CDN domains that match the certificate domain list.
# If no matching CDN domain exists, this step is skipped.
CDN_ENABLED = True
CDN_CERT_NAME = ""


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
# ACMEClient  --  Let's Encrypt RFC 8555 (HTTP-01 challenge)
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

    def get_http_challenge(self, authorization):
        for challenge in authorization['challenges']:
            if challenge['type'] == 'http-01':
                return challenge
        raise Exception("No http-01 challenge found")

    def compute_http_challenge(self, challenge):
        token = challenge['token']
        jwk_json = json.dumps(self._jwk(), sort_keys=True, separators=(',', ':'))
        thumbprint = hashlib.sha256(jwk_json.encode('utf-8')).digest()
        key_authorization = token + "." + b64url(thumbprint)
        challenge_path = f"/.well-known/acme-challenge/{token}"
        return challenge_path, key_authorization

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
# HuaweiELBClient  --  ELB v3 REST API (certificate + listener + L7 policy)
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

    def ensure_enhance_l7policy_enabled(self, listener_id):
        url = self._url(f"listeners/{listener_id}")
        resp = requests.get(url, headers=self.headers, timeout=30)
        if resp.status_code != 200:
            raise Exception(f"Get listener failed: {resp.status_code} {resp.text}")
        listener = resp.json().get("listener", {})
        if listener.get("enhance_l7policy_enable", False):
            return
        update_resp = requests.put(url, json={"listener": {"enhance_l7policy_enable": True}},
                                   headers=self.headers, timeout=30)
        if update_resp.status_code not in (200, 201):
            raise Exception(
                f"enhance_l7policy_enable is false and could not be enabled: "
                f"{update_resp.status_code} {update_resp.text}"
            )

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

    # --- L7 Policy (for HTTP-01 challenge) ---

    def list_l7_policies(self, listener_id):
        url = self._url("l7policies")
        resp = requests.get(
            url, params={"listener_id": listener_id},
            headers=self.headers, timeout=30
        )
        if resp.status_code != 200:
            raise Exception(f"List L7 policies failed: {resp.status_code} {resp.text}")
        return resp.json().get("l7policies", [])

    def create_l7_policy_fixed_response(self, listener_id, name, message_body,
                                        challenge_path,
                                        status_code="200", content_type="text/plain"):
        url = self._url("l7policies")
        policy_body = {
            "l7policy": {
                "listener_id": listener_id,
                "action": "FIXED_RESPONSE",
                "name": name,
                "priority": 1,
                "fixed_response_config": {
                    "status_code": str(status_code),
                    "content_type": content_type,
                    "message_body": message_body
                },
                "rules": [
                    {
                        "type": "PATH",
                        "compare_type": "EQUAL_TO",
                        "value": challenge_path
                    }
                ]
            }
        }
        resp = requests.post(url, json=policy_body, headers=self.headers, timeout=30)
        if resp.status_code in (200, 201):
            return resp.json()["l7policy"]["id"]
        raise Exception(
            f"Create L7 policy failed: {resp.status_code} {resp.text}"
        )

    def shift_l7_priorities(self, listener_id, delta=1):
        existing = self.list_l7_policies(listener_id)
        shifted = []
        for p in existing:
            orig_priority = p.get("priority")
            if orig_priority is not None:
                new_priority = orig_priority + delta
                update_url = self._url(f"l7policies/{p['id']}")
                resp = requests.put(update_url, json={"l7policy": {"priority": new_priority}},
                                    headers=self.headers, timeout=30)
                if resp.status_code in (200, 201):
                    shifted.append((p["id"], orig_priority))
                else:
                    raise Exception(
                        f"Shift L7 priority failed for {p['id']}: {resp.status_code} {resp.text}"
                    )
        return shifted

    def restore_l7_priorities(self, shifted):
        for policy_id, orig_priority in shifted:
            try:
                update_url = self._url(f"l7policies/{policy_id}")
                requests.put(update_url, json={"l7policy": {"priority": orig_priority}},
                             headers=self.headers, timeout=30)
            except Exception:
                pass

    def delete_l7_policy(self, policy_id):
        url = self._url(f"l7policies/{policy_id}")
        resp = requests.delete(url, headers=self.headers, timeout=30)
        if resp.status_code not in (200, 204):
            raise Exception(f"Delete L7 policy failed: {resp.status_code} {resp.text}")


# ===========================================================================
# HuaweiCCMClient  --  CCM (SCM) REST API: hosted certificate management
# ===========================================================================

class HuaweiCCMClient:
    def __init__(self, token, ccm_region):
        self.endpoint = f"https://scm.{ccm_region}.myhuaweicloud.com"
        self.headers = {
            "X-Auth-Token": token,
            "Content-Type": "application/json"
        }

    def _list_certificates(self):
        certs = []
        offset = 0
        while True:
            url = f"{self.endpoint}/v3/scm/certificates"
            params = {"limit": 50, "offset": offset}
            resp = requests.get(url, params=params, headers=self.headers, timeout=30)
            if resp.status_code != 200:
                raise Exception(f"CCM list certificates failed: {resp.status_code} {resp.text}")
            data = resp.json()
            page = data.get("certificates", [])
            certs.extend(page)
            if len(page) < 50 or len(certs) >= data.get("total_count", 0):
                break
            offset += 50
        return certs

    def find_certificate_by_name(self, name):
        for cert in self._list_certificates():
            if cert.get("name") == name:
                return cert
        return None

    def import_certificate(self, name, cert_pem, key_pem):
        url = f"{self.endpoint}/v3/scm/certificates/import"
        body = {
            "name": name,
            "certificate": cert_pem,
            "private_key": key_pem,
        }
        resp = requests.post(url, json=body, headers=self.headers, timeout=30)
        if resp.status_code != 200:
            raise Exception(f"CCM import certificate failed: {resp.status_code} {resp.text}")
        return resp.json()["certificate_id"]

    def delete_certificate(self, cert_id):
        url = f"{self.endpoint}/v3/scm/certificates/{cert_id}"
        resp = requests.delete(url, headers=self.headers, timeout=30)
        if resp.status_code != 204:
            raise Exception(f"CCM delete certificate failed: {resp.status_code} {resp.text}")

    def upsert_certificate(self, name, cert_pem, key_pem):
        existing = self.find_certificate_by_name(name)
        if existing:
            self.delete_certificate(existing["id"])
            action = "updated"
        else:
            action = "created"
        cert_id = self.import_certificate(name, cert_pem, key_pem)
        return cert_id, action


# ===========================================================================
# Huawei CDN Client  --  deploy certificate to CDN domains
# ===========================================================================

class HuaweiCDNClient:
    def __init__(self, token):
        self.endpoint = "https://cdn.myhuaweicloud.com"
        self.headers = {
            "X-Auth-Token": token,
            "Content-Type": "application/json"
        }

    def list_domains(self):
        domains = []
        page_number = 1
        while True:
            url = f"{self.endpoint}/v1.0/cdn/domains"
            params = {"page_size": 100, "page_number": page_number, "enterprise_project_id": "all"}
            resp = requests.get(url, params=params, headers=self.headers, timeout=30)
            if resp.status_code != 200:
                raise Exception(f"CDN list domains failed: {resp.status_code} {resp.text}")
            data = resp.json()
            page = data.get("domains") or []
            domains.extend(page)
            if len(page) < 100:
                break
            page_number += 1
        return domains

    def find_matching_domains(self, cert_domains):
        matching = []
        for cdn_domain in self.list_domains():
            domain_name = cdn_domain.get("domain_name", "")
            for cert_domain in cert_domains:
                if cert_domain.startswith("*."):
                    base = cert_domain[2:]
                    if domain_name == base or domain_name.endswith("." + base):
                        matching.append(domain_name)
                        break
                else:
                    if domain_name == cert_domain:
                        matching.append(domain_name)
                        break
        return list(set(matching))

    def update_certificate(self, domain_names, cert_pem, key_pem, cert_name):
        url = f"{self.endpoint}/v1.0/cdn/domains/config-https-info"
        body = {
            "https": {
                "domain_name": ",".join(domain_names),
                "https_switch": 1,
                "cert_name": cert_name,
                "certificate": cert_pem,
                "private_key": key_pem,
                "certificate_type": 0,
            }
        }
        resp = requests.put(url, json=body, headers=self.headers, params={"enterprise_project_id": "all"}, timeout=30)
        if resp.status_code != 200:
            raise Exception(f"CDN update certificate failed: {resp.status_code} {resp.text}")
        return resp.json()

    def deploy_certificate(self, cert_domains, cert_pem, key_pem, cert_name):
        matching = self.find_matching_domains(cert_domains)
        if not matching:
            return [], "skip", "No matching CDN domains found"
        result = self.update_certificate(matching, cert_pem, key_pem, cert_name)
        status = result.get("status", "success")
        return matching, "updated" if status == "success" else "error", result


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
# MAIN HANDLER  --  FunctionGraph entry point (HTTP-01 challenge)
# ===========================================================================

def handler(event, context):
    import traceback

    cfg_domain = DOMAIN
    cfg_domains = DOMAINS
    cfg_cert_name = CERT_NAME
    cfg_region = REGION
    cfg_project_id = PROJECT_ID
    cfg_http_listener_id = HTTP_LISTENER_ID
    cfg_acme_url = ACME_DIRECTORY_URL
    cfg_account_email = ACCOUNT_EMAIL
    cfg_renew_before = RENEW_BEFORE_DAYS
    cfg_ccm_enabled = CCM_ENABLED
    cfg_ccm_cert_name = CCM_CERT_NAME
    cfg_ccm_region = CCM_REGION
    cfg_cdn_enabled = CDN_ENABLED
    cfg_cdn_cert_name = CDN_CERT_NAME

    if isinstance(event, str):
        try:
            event = json.loads(event)
        except Exception:
            event = {}
    if event is None:
        event = {}

    cfg_domain = event.get("domain", cfg_domain)
    cfg_domains = event.get("domains", cfg_domains)
    cfg_cert_name = event.get("cert_name", cfg_cert_name)
    cfg_region = event.get("region", cfg_region)
    cfg_project_id = event.get("project_id", cfg_project_id)
    cfg_http_listener_id = event.get("http_listener_id", cfg_http_listener_id)
    cfg_acme_url = event.get("acme_directory_url", cfg_acme_url)
    cfg_account_email = event.get("account_email", cfg_account_email)
    cfg_renew_before = event.get("renew_before_days", cfg_renew_before)
    cfg_ccm_enabled = event.get("ccm_enabled", cfg_ccm_enabled)
    cfg_ccm_cert_name = event.get("ccm_cert_name", cfg_ccm_cert_name)
    cfg_ccm_region = event.get("ccm_region", cfg_ccm_region)
    cfg_cdn_enabled = event.get("cdn_enabled", cfg_cdn_enabled)
    cfg_cdn_cert_name = event.get("cdn_cert_name", cfg_cdn_cert_name)
    force_renew = event.get("force_renew", False)

    cleanup_policies = []
    shifted_priorities = []
    elb_client = None
    ssl_wrapper = None
    acme = None

    try:
        if not cfg_http_listener_id or cfg_http_listener_id == "your-http-listener-id-here":
            raise Exception(
                "HTTP_LISTENER_ID is not configured. "
                "Run the setup script or pass http_listener_id via event."
            )

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

        # --- 3. Obtain certificate via Let's Encrypt HTTP-01 ---
        ssl_wrapper = OpenSSLWrapper()
        acme = ACMEClient(cfg_acme_url, ssl_wrapper)
        acme.register_account(contact_emails=[cfg_account_email])

        order = acme.create_order(cfg_domains)

        # Ensure enhance_l7policy_enable is true (required for FIXED_RESPONSE)
        elb_client.ensure_enhance_l7policy_enabled(cfg_http_listener_id)

        # Shift existing L7 policy priorities up by 100 to make room for our
        # challenge policies at priority 1 (highest priority)
        shifted_priorities = elb_client.shift_l7_priorities(cfg_http_listener_id, delta=100)

        for auth_url in order['authorizations']:
            auth = acme.get_authorization(auth_url)
            challenge = acme.get_http_challenge(auth)
            challenge_path, key_auth = acme.compute_http_challenge(challenge)

            token_short = challenge['token'][:16]
            policy_name = f"acme-challenge-{token_short}"

            # Create L7 policy (FIXED_RESPONSE) on the HTTP listener
            # This intercepts requests to /.well-known/acme-challenge/<token>
            # and returns the key authorization as a 200 text/plain response
            # The rule is created inline with the policy
            policy_id = elb_client.create_l7_policy_fixed_response(
                cfg_http_listener_id, policy_name, key_auth, challenge_path
            )
            cleanup_policies.append(policy_id)

            # Wait for the L7 policy to take effect
            time.sleep(5)

            # Tell Let's Encrypt to validate the challenge
            acme.answer_challenge(challenge['url'])
            acme.poll_authorization(auth_url)

        # --- Finalize the order ---
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

        # --- 4b. Upload to CCM (Cloud Certificate Manager) as hosted certificate ---
        ccm_result = None
        if cfg_ccm_enabled:
            try:
                ccm_client = HuaweiCCMClient(token, cfg_ccm_region)
                ccm_cert_name = cfg_ccm_cert_name or cfg_cert_name
                ccm_cert_id, ccm_action = ccm_client.upsert_certificate(
                    ccm_cert_name, cert_pem, cert_key_pem
                )
                ccm_result = {
                    "status": "success",
                    "cert_id": ccm_cert_id,
                    "cert_name": ccm_cert_name,
                    "cert_action": ccm_action,
                }
            except Exception as ccm_err:
                ccm_result = {
                    "status": "error",
                    "error": str(ccm_err),
                }

        # --- 4c. Deploy to CDN (Content Delivery Network) ---
        cdn_result = None
        if cfg_cdn_enabled:
            try:
                cdn_client = HuaweiCDNClient(token)
                cdn_cert_name = cfg_cdn_cert_name or cfg_cert_name
                cdn_domains, cdn_action, cdn_detail = cdn_client.deploy_certificate(
                    cfg_domains, cert_pem, cert_key_pem, cdn_cert_name
                )
                cdn_result = {
                    "status": "success" if cdn_action != "error" else "error",
                    "domains": cdn_domains,
                    "cert_name": cdn_cert_name,
                    "action": cdn_action,
                }
            except Exception as cdn_err:
                cdn_result = {
                    "status": "error",
                    "error": str(cdn_err),
                }

        # --- 5. Report listeners ---
        bound_listeners = []

        if cert_action == "updated":
            using_listeners = elb_client.find_listeners_by_cert(cert_id)
            for l in using_listeners:
                bound_listeners.append({
                    "id": l["id"],
                    "name": l.get("name", l["id"]),
                    "status": "auto-updated"
                })

        result = {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "status": "success",
                "message": "Certificate issued and deployed successfully (HTTP-01 challenge)",
                "domain": cfg_domain,
                "domains": cfg_domains,
                "cert_name": cert_actual_name,
                "cert_id": cert_id,
                "cert_action": cert_action,
                "listeners": bound_listeners,
                "ccm": ccm_result,
                "cdn": cdn_result,
                "project_id": project_id,
                "project_id_source": "auto" if project_id != cfg_project_id else "fallback",
                "challenge_type": "http-01"
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
        # Cleanup: delete all L7 policies created for the challenge
        if elb_client:
            for policy_id in cleanup_policies:
                try:
                    elb_client.delete_l7_policy(policy_id)
                except Exception:
                    pass
            # Restore original L7 policy priorities
            if shifted_priorities:
                elb_client.restore_l7_priorities(shifted_priorities)
        # Free RSA keys
        if ssl_wrapper and acme:
            try:
                ssl_wrapper.free_rsa(acme.account_rsa)
            except Exception:
                pass
