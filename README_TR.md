# Huawei Cloud ELB SSL Sertifikası Otomasyonu

Huawei Cloud ELB uzerinde Let's Encrypt sertifikalarinin **tam otomatik** yonetimi.
FunctionGraph (serverless) uzerinde her gun calisan bir Python fonksiyonu, sertifika alir,
Huawei ELB'ye yukler ve listener'lari gunceller. Disaridan hicbir mudahale gerekmez.

Iki challenge tipi desteklenir:
- **DNS-01** (`letsencrypt_dns.py`): Huawei Cloud DNS veya Cloudflare DNS TXT kayitlari kullanilir. Wildcard desteklenir.
- **HTTP-01** (`letsencrypt_http.py`): ELB L7 policy (FIXED_RESPONSE) ile port 80 uzerinden. DNS saglayici gerekmez.

## Ozellikler

- **Tam otomatik**: Gunluk timer trigger ile sertifika yenileme
- **Cift challenge**: DNS-01 (Huawei/Cloudflare DNS) veya HTTP-01 (ELB L7 policy)
- **Wildcard destek**: `*.domain.com` formatinda wildcard sertifikalar (sadece DNS-01)
- **Coklu domain**: Ayni setup script'i farkli domain'ler icin tekrar calistirilabilir
- **Cift DNS saglayici**: DNS-01 challenge icin Huawei Cloud DNS veya Cloudflare DNS
- **KooCLI gerekmez**: Sadece AK/SK ile calisir, pip paketi gerekmez
- **CSV credential import**: Script dizinindeki CSV dosyasindan AK/SK otomatik alinir
- **Subdomain zone fallback**: DNS zone aramasi parent domain'e fallback yapar (orn: `test1.batur.site` -> `batur.site`)
- **OpenSSL ctypes ile**: `libcrypto` direkt yuklenir, `pip install` gerekmez
- **ELB bagimsiz**: Sertifika domain ile eslesir, ELB adi gerekmez
- **Rate limit korumasi**: >30 gun gecerli sertifikalar yenilenmez

## Mimari

### DNS-01 Challenge

```
                   Timer Trigger (gunluk 3 AM)
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
    (TXT kaydi)
```

### HTTP-01 Challenge

```
                   Timer Trigger (gunluk 3 AM)
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

**HTTP-01 Akis:**
1. Domain ile eslesen sertifika var mi? -> >30 gun gecerliyse yenilemeyi atla
2. Her domain icin port 80 listener'da L7 policy (FIXED_RESPONSE) olustur
   - Policy, `/.well-known/acme-challenge/<token>` yolunu esler (PATH EQUAL_TO)
   - `200 text/plain <key_authorization>` doner
3. Let's Encrypt `http://<domain>/.well-known/acme-challenge/<token>` istegiyle dogrular
4. Sertifika indir -> ELB'ye yukle (varsa update, yoksa create)
5. Temizlik: tum L7 policy'leri sil (`finally` blogunda)

## Onkosullar

### DNS-01 Challenge
1. Huawei Cloud hesabi ve AK/SK (IAM admin yetkileri ile)
2. DNS public zone olusturulmus (Huawei Cloud DNS **veya** Cloudflare DNS, domain icin)
3. Python 3.x (setup script'i calistirmak icin, FunctionGraph icin degil)
4. Cloudflare DNS kullaniliyorsa: `Zone:DNS:Edit` yetkili bir Cloudflare API Token
   (`https://dash.cloudflare.com/profile/api-tokens` adresinden olusturulur)

### HTTP-01 Challenge
1. Huawei Cloud hesabi ve AK/SK (IAM admin yetkileri ile)
2. Domain'in DNS A kaydi bir Huawei ELB'nin public IP'sine yonlenmeli
3. ELB'de **HTTP** (TCP degil) listener **port 80**'de olmali
4. Python 3.x (setup script'i calistirmak icin, FunctionGraph icin degil)
5. DNS saglayici veya DNS zone gerekmez

## Kurulum

### DNS-01 Kurulumu

```powershell
python setup_letsencrypt_fg_tr.py
```

Wizard tum parametreleri adim adim sorar:

```
  'credentials.csv' dosyasinda credential bulundu (kullanici: H00XXXX, AK: HPUA...QPWJ)
  Kabul icin Enter'a basin, veya override icin yazin.

  Huawei Access Key ID (AK) [***]:
  Huawei Secret Access Key (SK) [***]:
  Region [tr-west-1]:
  Domain [example.com]: example.com
  Wildcard sertifika? (*.domain tum subdomain'leri kapsar) [Y/n]: y
  DNS saglayici [1=Huawei Cloud DNS / 2=Cloudflare DNS] [1]: 2

  Cloudflare DNS secildi. Cloudflare API Token gereklidir
  (ilgili zone icin 'Zone:DNS:Edit' yetkisi ile).
  Olustur: https://dash.cloudflare.com/profile/api-tokens

  Cloudflare API Token [***]:
  Cloudflare Zone ID (bos = otomatik bul):
  Sertifika adi [letsencrypt-test1-batur-site]:
  ...
```

### HTTP-01 Kurulumu

```powershell
python setup_letsencrypt_http_fg_tr.py
```

Wizard domain IP'sini resolve eder ve ELB ile eslestirir:

```
  Huawei Access Key ID (AK) [***]:
  Huawei Secret Access Key (SK) [***]:
  Region [tr-west-1]:
  Domain [example.com]: example.com

  Not: HTTP-01 challenge wildcard sertifikalari DESTEKLEMEZ.
  Her domain ELB'nin public IP'sine yonlenmeli.

  Ek domain'ler (SAN, virgulle ayrilmis, bos = yok): www.example.com
  Sertifika adi [letsencrypt-example-com]:
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

Domain IP'si hicbir ELB ile eslesmezse script sonlanir:
```
  ERROR: Domain 'example.com' (1.2.3.4) does not match any ELB.
  HTTP-01 challenge will NOT work because Let's Encrypt cannot reach
  the challenge endpoint via http://example.com/.well-known/acme-challenge/
```

### CSV Credential Dosyasi

Script dizininde su basliklara sahip bir `.csv` dosyasi varsa:

```
User Name,Access Key Id,Secret Access Key
```

Wizard otomatik olarak AK/SK'yi ilk veri satirindan alir.
Kabul icin Enter'a basin, veya override icin yazin.

Ornek CSV (`credentials.csv`):

```csv
User Name,Access Key Id,Secret Access Key
HXXXX,HPUAXXXX,XXXXXXXXXXXX
```

### Kurulum Adimlari

#### DNS-01 Kurulum Adimlari
1. IAM token al (project-scoped + domain-scoped)
2. DNS zone ve ELB dogrula
   - Huawei DNS: zone lookup Huawei DNS API ile (parent domain fallback ile)
   - Cloudflare DNS: zone lookup Cloudflare API ile (parent domain fallback ile)
3. IAM custom policy olustur (`dns:*:*` + `elb:*:*`)
4. IAM agency olustur (FunctionGraph'a trust)
5. Policy'yi agency'ye ata (all-projects)
6. FunctionGraph function olustur
7. Function kodu yukle (config uygulananmis halde)
8. Timer trigger ekle (cron `0 0 3 * * ?`)
9. Domain-specific script kopyasi kaydet
10. (Opsiyonel) Function'i invoke et - ilk sertifika alimi (~60 saniye)

#### HTTP-01 Kurulum Adimlari
1. IAM token al (project-scoped + domain-scoped)
2. Domain sor (wildcard desteklenmez)
3. Domain IP'sini DNS lookup ile resolve et
4. Tum ELB'leri listele, public IP'si domain IP'si ile eslesen ELB'yi bul
   - Eslesme yoksa -> cikis (HTTP-01 calismaz)
5. Eslesen ELB'de port 80 HTTP listener'i bul
   - Port 80 HTTP listener yoksa -> cikis
6. Listener'daki mevcut L7 policy'leri kontrol et (cakisma uyari)
7. IAM custom policy olustur (sadece `elb:*:*`)
8. IAM agency olustur (FunctionGraph'a trust)
9. Policy'yi agency'ye ata (all-projects)
10. FunctionGraph function olustur
11. Function kodu yukle (config uygulananmis halde)
12. Timer trigger ekle (cron `0 0 3 * * ?`)
13. Domain-specific script kopyasi kaydet
14. (Opsiyonel) Function'i invoke et - ilk sertifika alimi (~60 saniye)

### Coklu Domain

Ayni script'i farkli domain'ler icin tekrar calistirin. Her domain icin ayri kaynaklar olusturulur:

| Challenge | Domain | Function | Timer | Cert |
|---|---|---|---|---|
| DNS-01 | `example.com` | `letsencrypt-dns-example-com` | `daily-cert-renewal-example-com` | `letsencrypt-example-com` |
| HTTP-01 | `example.com` | `letsencrypt-http-example-com` | `daily-cert-renewal-http-example-com` | `letsencrypt-example-com` |

Agency (`fg-letsencrypt`) paylasimlidir.

## Dosyalar

| Dosya | Aciklama |
|---|---|
| `letsencrypt_dns.py` | DNS-01 ANA SCRIPT - FunctionGraph function kodu |
| `letsencrypt_http.py` | HTTP-01 ANA SCRIPT - FunctionGraph function kodu |
| `setup_letsencrypt_fg.py` | DNS-01 kurulum wizard'i (Ingilizce) |
| `setup_letsencrypt_fg_tr.py` | DNS-01 kurulum wizard'i (Turkce) |
| `setup_letsencrypt_http_fg.py` | HTTP-01 kurulum wizard'i (Ingilizce) |
| `setup_letsencrypt_http_fg_tr.py` | HTTP-01 kurulum wizard'i (Turkce) |
| `AGENTS.md` | AI asistanlari icin detayli dokumantasyon |
| `README.md` | Ingilizce README |
| `README_TR.md` | Turkce README (bu dosya) |
| `letsencrypt_dns_{domain}.py` | DNS-01 domain-specific kopyalar |
| `letsencrypt_http_{domain}.py` | HTTP-01 domain-specific kopyalar |
| `credentials.csv` | (Opsiyonel) AK/SK auto-import icin CSV |

## Manuel Invoke (Event Override)

FunctionGraph konsolundan veya API uzerinden event gondererek config'i override edebilirsiniz:

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

Bos event `{}` default config'i kullanir (timer trigger bos event gonderir).

## Config Parametreleri

### DNS-01 Config

| Parametre | Default | Aciklama |
|---|---|---|
| `DOMAIN` | `example.com` | Ana domain |
| `DOMAINS` | `["example.com", "www.example.com"]` | SAN listesi |
| `ZONE_ID` | - | Huawei DNS zone ID |
| `ZONE_NAME` | - | Huawei DNS zone adi (subdomain'ler icin domain'den farkli olabilir) |
| `CERT_NAME` | - | Sertifika adi |
| `REGION` | `tr-west-1` | Huawei Cloud region |
| `ACME_DIRECTORY_URL` | Let's Encrypt production | ACME endpoint |
| `RENEW_BEFORE_DAYS` | `30` | Yenileme esigi (gun) |
| `DNS_PROVIDER` | `huawei` | DNS saglayici: `huawei` veya `cloudflare` |
| `CLOUDFLARE_API_TOKEN` | `` | Cloudflare API token (`cloudflare` ise gerekli) |
| `CLOUDFLARE_ZONE_ID` | `` | Cloudflare zone ID (`cloudflare` ise gerekli) |
| `force_renew` | `false` | Expire kontrolunu atla |

### HTTP-01 Config

| Parametre | Default | Aciklama |
|---|---|---|
| `DOMAIN` | `example.com` | Ana domain |
| `DOMAINS` | `["example.com"]` | SAN listesi (wildcard yok) |
| `CERT_NAME` | - | Sertifika adi |
| `REGION` | `tr-west-1` | Huawei Cloud region |
| `HTTP_LISTENER_ID` | - | Port 80 HTTP listener ID |
| `ACME_DIRECTORY_URL` | Let's Encrypt production | ACME endpoint |
| `ACCOUNT_EMAIL` | `mailto:admin@example.com` | ACME account email |
| `RENEW_BEFORE_DAYS` | `30` | Yenileme esigi (gun) |
| `force_renew` | `false` | Expire kontrolunu atla |

## Test Senaryolari

### DNS-01 Testleri

#### Skip (mevcut cert gecerli)
Bos event -> `status: "skip"`, `days_left: 89`

#### Yeni cert olusturma
Event ile yeni domain -> `cert_action: "created"`, `listeners: []` (~55 saniye)

#### Cert yenileme
`force_renew: true` -> `cert_action: "updated"`, listener listesi dolu

#### Wildcard
`domains: ["*.example.com", "example.com"]` -> TXT kaydi `_acme-challenge.example.com.` adresine yazilir

#### Cloudflare DNS
`DNS_PROVIDER`'i `cloudflare` yapin (veya setup wizard'da `2` secenegini secin). DNS-01 challenge
icin TXT kaydi Huawei DNS yerine Cloudflare API ile olusturulur. Cloudflare API token function
koduna gomulur (FunctionGraph'a upload edilir), cunku Huawei agency Cloudflare credential'lari alamaz.

### HTTP-01 Testleri

#### Skip (mevcut cert gecerli)
Bos event -> `status: "skip"`, `days_left: 89`

#### HTTP-01 ile yeni cert olusturma
```json
{
  "domain": "example.com",
  "domains": ["example.com"],
  "http_listener_id": "cd58...",
  "cert_name": "letsencrypt-example-com"
}
```
-> `cert_action: "created"`, `challenge_type: "http-01"` (~55 saniye)

#### HTTP-01 ile cert yenileme
`force_renew: true` -> `cert_action: "updated"`, listener listesi dolu

#### HTTP-01 ile coklu domain
```json
{
  "domain": "example.com",
  "domains": ["example.com", "www.example.com"],
  "http_listener_id": "cd58..."
}
```
Her domain icin ayri L7 policy olusturulur (farkli token = farkli yol). Tum policy'ler temizlenir.

## Notlar

- **Let's Encrypt rate limit**: Ayni domain icin haftada 50 cert. `force_renew`'i dikkatli kullanin.
- **Staging**: Test icin `ACME_DIRECTORY_URL`'i staging yapin.
- **IAM yetkileri**: AK/SK'nin IAM admin yetkileri olmali (policy/agency olusturmak icin).
- **DNS zone (DNS-01)**: Domain veya parent domain icin public zone olusturulmus olmali.
  Subdomain'ler otomatik olarak parent zone'a fallback yapar (orn: `test1.batur.site` -> `batur.site.` zone).
  Cloudflare DNS icin zone Cloudflare API ile aranir.
- **Cloudflare API token (DNS-01)**: Hedef zone icin `Zone:DNS:Edit` yetkisi gerekli.
  Token function koduna gomulur (Cloudflare icin Huawei agency entegrasyonu yoktur).
- **ELB**: HTTPS listener olusturulmus olmali (sertifika domain ile eslesir).
- **HTTP-01 wildcard**: HTTP-01 challenge wildcard sertifikalari DESTEKLEMEZ. Wildcard icin DNS-01 kullanin.
- **HTTP-01 domain-to-ELB**: Domain'in DNS A kaydi ELB'nin public IP'sine yonlenmeli.
  Setup script bunu kontrol eder, eslesme yoksa sonlanir.
- **HTTP-01 port 80 listener**: ELB'de HTTP (TCP degil) listener port 80'de olmali.
  L7 policy'ler (FIXED_RESPONSE) sadece HTTP/HTTPS listener'larda calisir.
- **HTTP-01 L7 policy `message_body`**: `fixed_response_config` alani `message_body`'dir (`body` DEGIL).
- **HTTP-01 L7 policy `priority`**: `priority` kullanin (`position` degil). `position` deprecated.
  Kucuk priority = yuksek oncelik. Aralik 1-10000.
- **HTTP-01 `enhance_l7policy_enable`**: `fixed_response_config`, listener'da `enhance_l7policy_enable=true`
  gerektirir. Shared load balancer'lar icin desteklenmeyebilir.
- **HTTP-01 L7 policy temizlik**: L7 policy'ler `finally` blogunda silinir.
  Function olusum ve temizlik arasinda crash olursa, policy'ler listener'da kalabilir.
  Function'i tekrar calistirmak veya manuel silmek guvenlidir.

## Teknoloji

- **Python 3.10** (FunctionGraph runtime)
- **requests** (FunctionGraph runtime'inda mevcut)
- **ctypes** (OpenSSL libcrypto'ya direkt erisim)
- **Huawei Cloud**: FunctionGraph, DNS, ELB v3, IAM
- **Cloudflare**: DNS REST API (opsiyonel, DNS-01 challenge icin)
- **Let's Encrypt**: ACME v2 (RFC 8555), DNS-01 ve HTTP-01 challenge
