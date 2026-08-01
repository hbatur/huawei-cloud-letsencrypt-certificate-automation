# huawei-cloud-letsencrypt-certificate-automation
Fully automated Let's Encrypt SSL certificate management for Huawei Cloud ELB. Serverless Python function on FunctionGraph renews certificates daily via DNS-01 (Huawei/Cloudflare DNS) or HTTP-01 (ELB L7 policy) challenge. No manual intervention, no pip dependencies, wildcard support.
