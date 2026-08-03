# Kurulum Rehberi

Huawei Cloud ELB uzerinde Let's Encrypt SSL sertifikalarinin tam otomatik yonetimi icin adim adim kurulum.

---

## 1. Onkosullar

### Genel (her iki yontem icin)

| # | Gereksinim |
|---|---|
| 1 | Huawei Cloud hesabi |
| 2 | AK/SK (IAM admin yetkileri ile) — My Credentials > Access Keys |
| 3 | Python 3.x (setup script'i yerel makinede calistirmak icin) |
| 4 | `requests` kutuphanesi (`pip install requests`) |

### DNS-01 icin ek

| # | Gereksinim |
|---|---|
| 5 | DNS public zone (Huawei Cloud DNS **veya** Cloudflare DNS) |
| 6 | Cloudflare kullaniliyorsa: `Zone:DNS:Edit` yetkili API Token |

### HTTP-01 icin ek

| # | Gereksinim |
|---|---|
| 5 | Domain'in A kaydi ELB'nin public IP'sine yonlenmeli |
| 6 | ELB'de **HTTP** (TCP degil) listener **port 80**'de olmali |

---

## 2. Yontem Secimi

```
                    Wildcard lazim mi?
                         /        \
                       EVET        HAYIR
                        |            |
                   DNS-01          DNS erisim var mi?
                 (TXT kaydi)         /        \
                              EVET          HAYIR
                               |              |
                           DNS-01         HTTP-01
                         (TXT kaydi)    (ELB L7 policy)
```

| Ozellik | DNS-01 | HTTP-01 |
|---|---|---|
| Wildcard (`*.domain`) | Evet | Hayir |
| DNS saglayici | Gerekli | Gerekmez |
| ELB port 80 listener | Gerekmez | Gerekli |
| Setup script | `setup_letsencrypt_fg_tr.py` | `setup_letsencrypt_http_fg_tr.py` |

---

## 3. Kurulum — DNS-01

### 3.1 Script'i calistir

```powershell
python setup_letsencrypt_fg_tr.py
```

### 3.2 Wizard sorularini yanitla

Asagidaki gibi sorular gelecek. Kose parantez `[...]` icindekiler default degerdir — kabul icin **Enter**'a basin.

```
Huawei Access Key ID (AK): HPUAXXXXXXXXXXXX
Huawei Secret Access Key (SK): ********
Region [tr-west-1]:
Domain: example.com
Wildcard sertifika? (*.domain tum subdomain'leri kapsar) [Y/n]: y
DNS saglayici [1=Huawei Cloud DNS / 2=Cloudflare DNS] [1]: 1
Sertifika adi [letsencrypt-example-com]:
```

**Cloudflare secerseniz** ek olarak:
```
Cloudflare API Token: ********
Cloudflare Zone ID (bos = otomatik bul):
```

### 3.3 Wizard ne yapar?

```
[1] IAM token aliniyor...
[2] DNS zone dogrulaniyor...
[3] IAM policy olusturuluyor...     (dns + elb + scm + cdn yetkileri)
[4] IAM agency olusturuluyor...     (fg-letsencrypt)
[5] Policy agency'ye ataniyor...
[6] FunctionGraph function olusturuluyor...
[7] Function kodu yukleniyor...
[8] Timer trigger ekleniyor...       (her gun 3 AM)
[9] Domain-specific kopya kaydediliyor...
[10] Function invoke ediliyor...     (ilk sertifika ~60 sn)
```

### 3.4 Tamamlandiginda olusan kaynaklar

| Kaynak | Ad |
|---|---|
| Function | `letsencrypt-dns-example-com` |
| Timer | `daily-cert-renewal-example-com` |
| Agency | `fg-letsencrypt` (paylasimli) |
| Policy | `letsencrypt-example-com-policy` |
| Script kopyasi | `letsencrypt_dns_example-com.py` |

---

## 4. Kurulum — HTTP-01

### 4.1 Script'i calistir

```powershell
python setup_letsencrypt_http_fg_tr.py
```

### 4.2 Wizard sorularini yanitla

```
Huawei Access Key ID (AK): HPUAXXXXXXXXXXXX
Huawei Secret Access Key (SK): ********
Region [tr-west-1]:
Domain: example.com

  Not: HTTP-01 wildcard DESTEKLEMEZ.

Ek domain'ler (SAN, virgulle ayrilmis, bos = yok): www.example.com
Sertifika adi [letsencrypt-example-com]:
```

### 4.3 Otomatik ELB eslestirme

Wizard domain IP'sini resolve eder ve ELB ile eslestirir:

```
[2] Resolving domain IP: example.com -> 1.2.3.4
[3] ELB eslestiriliyor...
    Matched ELB: my-elb (id: xxx)
[4] Port 80 HTTP listener bulunuyor...
    Found listener: http-listener (id: cd58...)
[5] L7 policy kontrolu...
```

> **Hata alirsaniz:** Domain IP'si hicbir ELB ile eslesmezse script sonlanir.
> Cozum: Domain'in A kaydinin ELB'nin public IP'sine baktigindan emin olun.

### 4.4 Wizard ne yapar?

```
[1] IAM token aliniyor...
[2] Domain IP resolve ediliyor...
[3] ELB eslestiriliyor...
[4] Port 80 HTTP listener bulunuyor...
[5] L7 policy kontrolu...
[6] IAM policy olusturuluyor...     (elb + scm + cdn yetkileri)
[7] IAM agency olusturuluyor...     (fg-letsencrypt)
[8] Policy agency'ye ataniyor...
[9] FunctionGraph function olusturuluyor...
[10] Function kodu yukleniyor...
[11] Timer trigger ekleniyor...      (her gun 3 AM)
[12] Domain-specific kopya kaydediliyor...
[13] Function invoke ediliyor...     (ilk sertifika ~60 sn)
```

---

## 5. CSV ile Otomatik Credential Import

Script dizinine `credentials.csv` koyun:

```csv
User Name,Access Key Id,Secret Access Key
H00XXXX,HPUAXXXX,XXXXXXXXXXXX
```

Wizard AK/SK'yi otomatik tespit eder, Enter'a basarak kabul edersiniz.

---

## 6. Coklu Domain

Ayni script'i farkli domain'ler icin **tekrar calistirin**. Her domain icin ayri kaynaklar olusturulur, onceki domain'ler uzerine yazilmaz.

```powershell
# 1. domain
python setup_letsencrypt_fg_tr.py    # -> example.com

# 2. domain
python setup_letsencrypt_fg_tr.py    # -> test.example.org
```

Agency (`fg-letsencrypt`) tum domain'ler arasinda paylasilir.

---

## 7. Dogrulama

Kurulumdan sonra kontrol edin:

| Adim | Nasil |
|---|---|
| Function olustu mu? | FunctionGraph konsolu > Functions |
| Timer trigger var mi? | Function > Triggers > cron `0 0 3 * * ?` |
| Ilk sertifika alindi mi? | ELB > Certificates > domain ile eslesen cert |
| Sertifika listener'a bagli mi? | ELB > Listeners > HTTPS listener > cert |

Ilk sertifika ~60 saniye surer. Hata alirsaniz Function log'larini kontrol edin.

---

## 8. Manuel Test (Event Override)

FunctionGraph konsolundan function'i manuel invoke edebilirsiniz.

### Zorla yenileme

```json
{
  "force_renew": true
}
```

### Yeni domain testi (DNS-01)

```json
{
  "domain": "test.example.com",
  "domains": ["test.example.com"],
  "cert_name": "letsencrypt-test-example-com"
}
```

### Yeni domain testi (HTTP-01)

```json
{
  "domain": "test.example.com",
  "domains": ["test.example.com"],
  "http_listener_id": "cd58...",
  "cert_name": "letsencrypt-test-example-com"
}
```

> Bos event `{}` default config'i kullanir (timer trigger boyle gonderir).

---

## 9. Sorun Giderme

| Sorun | Cozum |
|---|---|
| `403 Forbidden` | AK/SK'nin IAM admin yetkileri yok |
| `DNS zone not found` | Domain icin public zone olusturun (veya parent zone var mi kontrol edin) |
| `ELB not found` (HTTP-01) | Domain A kaydini ELB public IP'sine yonlendirin |
| `No port 80 HTTP listener` (HTTP-01) | ELB'ye HTTP protocol, port 80 listener ekleyin |
| `enhance_l7policy_enable false` (HTTP-01) | Wizard otomatik acar; acamazsa listener'i manuel duzenleyin |
| Sertifika alinamadi | Function log'larini kontrol edin; Let's Encrypt rate limit (haftada 50 cert/domain) |
| CCM hatasi | Non-fatal — ELB cert yine de basarili olur. CCM region: `cn-north-4`, `ap-southeast-1`, `my-kualalumpur-1` |
| CDN hatasi | Non-fatal — eslesen CDN domain yoksa skip edilir |

---

## 10. Test icin Staging

Production yerine Let's Encrypt staging kullanin (rate limit yok):

Event ile override:
```json
{
  "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"
}
```

---

## Dosya Referansi

| Dosya | Ne icin |
|---|---|
| `setup_letsencrypt_fg_tr.py` | DNS-01 kurulum (Turkce) |
| `setup_letsencrypt_fg.py` | DNS-01 kurulum (Ingilizce) |
| `setup_letsencrypt_http_fg_tr.py` | HTTP-01 kurulum (Turkce) |
| `setup_letsencrypt_http_fg.py` | HTTP-01 kurulum (Ingilizce) |
| `letsencrypt_dns.py` | DNS-01 function kodu (setup tarafindan upload edilir) |
| `letsencrypt_http.py` | HTTP-01 function kodu (setup tarafindan upload edilir) |
