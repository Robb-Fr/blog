---
title: "Building Coraza WAF for NGINX Docker image"
date: 2026-11-14
tags: nginx waf coraza owasp crs
---

We all know, these days more than ever, that having a WAF in front of your
publicly exposed web applications is great. This potentially catches known
and unknown exploits from reaching your backend servers and is what anyone
would hope for what a reverse proxy device is able to do.

I love NGINX, and don't want to switch to Traefik or Caddy, but still want a
modern WAF. Therefore, here's just how I brough up some sparsed pieces for
building the powerful modern WAF of Coraza by OWASP (<https://www.coraza.io/>)
to my NGINX setup, dockerised on RaspberryPi.

You can find all source files under <https://github.com/Robb-Fr/nginx-coraza-docker/>.

## Motivation

Weirdly, I could not find online a repo or docker image natively providing this.

I wanted to assess what would be the 2026 setup for adding a WAF on my NGINX
reverse proxy setup at home. I just love NGINX and don't want to change my
reverse proxy setup.

Looking at <https://www.f5.com/company/blog/nginx/f5-nginx-modsecurity-waf-transitioning-to-eol>,
I saw that the official ModSec module even for NGINX Plus was retired, notably
mentionning:
> OWASP ModSecurity Core Rule Set (CRS) project plans to continue its support
> for ModSecurity, it is transitioning its focus to a new WAF called Coraza,
> having concerns over the viability of the ModSecurity project given the
> actions and announcement to changes in support by Trustwave.

Therefore, I checked Coraza and it indeed seemed great, with an NGINX connector
and all. Looking at the instructions on <https://github.com/corazawaf/coraza-nginx>,
I realized things were not going to be this easy:

1. No pre-built version distributed for Debian
2. No pre-built Docker image either from F5 or Coraza

While I am using a dockerised setup on my home's Raspberry Pi (on Raspbian, not
Ubuntu).

I also wanted to have this WAF on my NGINX, hence this repo and Dockerfile.
I hope this can help some of you who like NGINX. Take a look at the comments
in the Dockerfile if you have questions, or you can also open an issue.

## Method

Nothing too fancy here (which is what makes it cool):

1. I build the `libcoraza` library in a `golang` Docker image
2. I build the third party module using NGINX's `configure` script and the `nginx-coraza`
connector built by Coraza
3. I fetch the CRS files <https://www.coraza.io/docs/tutorials/coreruleset/#manual-installation>
to be injected later in NGINX's conf
4. I perform inline with `sed` the basic modifications to make sure that WAF is
blocking and that logs will appear in the container's logs
5. Use the official NGINX image and inject the built dynamic modules (and no
further modifications in the NGINX official image which is cool)

This just puts together the different docs from libcoraza, nginx-coraza and nginx
with a concrete example (and my tests to ensure I get a real blocking WAF).

## Usage

Basically, to build your container image, just edit the first `ARG` in
[Dockerfile](./Dockerfile) to set your desired NGINX version (see versions on
<https://hub.docker.com/_/nginx>).

```Dockerfile
ARG nginx_version=<change to set your desired version>
```

You can then build the whole thing:

```bash
docker build -t nginx-coraza-waf .
# you could also pass dynamically the desired NGINX version:
# docker build --build-arg nginx_version=<desired-version> -t nginx-coraza-waf .
```

and you should get your Docker image that you can use afterward.

See [nginx.conf](./nginx.conf) for the directives you should include (not
necessarily at the `http {}` level, also works in `server {}` or `location {}`
blocks.)

Basically, to get a full OWASP Core Ruleset blocking mode from there,
you'll need:

```nginx
# Activates the Coraza WAF module
load_module modules/ngx_http_coraza_module.so;

...
http {
    # enabled module
    coraza on;
    # adds base file from https://github.com/corazawaf/coraza/blob/main/coraza.conf-recommended
    # with modification made at build time
    coraza_rules_file /etc/coraza/coraza.conf;
    # Uses defaults from https://github.com/coreruleset/coreruleset/blob/main/crs-setup.conf.example
    coraza_rules_file /etc/coraza/crs-setup.conf;
    # adds all CRS rules from https://github.com/coreruleset/coreruleset/tree/main/rules 
    coraza_rules_file /etc/coraza/rules/*.conf;
    
    ## Optional
    # I like to match transaction id of WAF with nginx request id, to match access_logs
    coraza_transaction_id "$request_id";
    # I also give the request id back in a header to the user, in case of false positive
    add_header X-Request-Id "$request_id";
    # See https://nginx.org/en/docs/http/ngx_http_headers_module.html
    # but basically imo you generally want this, at least I do
    add_header_inherit merge;
}
```

These should load into your configuration and startup NGINX with Coraza's WAF.

## Example

See the [docker-compose.yml](./docker-compose.yml) for an example usage of this
image in action.

```bash
docker compose build && docker compose down && docker compose up -d && docker compose logs -f
```

In another terminal, you can run the following:

```bash
curl -i "http://localhost:8080/" # should work fine
```

```txt
# example log:
nginx  | 192.168.65.1 - - [14/Nov/2026:20:11:07 +0000] "GET / HTTP/1.1" 200 896 "-" "curl/8.7.1" "-"
```

```bash
curl -i "http://localhost:8080/q=<script>alert()</script>" # should return 403 and show logs
````

```txt
# example log:
nginx  | 2026/11/14 20:12:31 [error] 29#29: *1 Coraza: Access denied with code 403, unique_id "0f3db12bb382a1584faca3cc6bf67cfd", client: 192.168.65.1, server: localhost, request: "GET /q=<script>alert()</script> HTTP/1.1", host: "localhost:8080"
nginx  | 192.168.65.1 - - [14/Nov/2026:20:12:31 +0000] "GET /q=<script>alert()</script> HTTP/1.1" 403 153 "-" "curl/8.7.1" "-"
nginx  | --eGHHtdBBsBCPabGh-A--
nginx  | [2026/11/14 20:12:31] 0f3db12bb382a1584faca3cc6bf67cfd 192.168.65.1 47270 172.18.0.2 80
nginx  | --eGHHtdBBsBCPabGh-B--
nginx  | GET /q=%3Cscript%3Ealert%28%29%3C/script%3E HTTP/1.1
nginx  | host: localhost:8080
nginx  | user-agent: curl/8.7.1
nginx  | accept: */*
nginx  | 
nginx  | --eGHHtdBBsBCPabGh-I--
nginx  | 
nginx  | --eGHHtdBBsBCPabGh-J--
nginx  | Total,0
nginx  | 
nginx  | --eGHHtdBBsBCPabGh-D--
nginx  | 
nginx  | --eGHHtdBBsBCPabGh-E--
nginx  | 
nginx  | --eGHHtdBBsBCPabGh-F--
nginx  | HTTP/1.1 403 Forbidden
nginx  | 
nginx  | --eGHHtdBBsBCPabGh-H--
nginx  | [client "192.168.65.1"] Coraza: Warning. XSS Filter - Category 1: Script Tag Vector [file "/etc/coraza/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [line "9226"] [id "941110"] [rev ""] [msg "XSS Filter - Category 1: Script Tag Vector"] [data "Matched Data: <script> found within REQUEST_FILENAME: /q=<script>alert()</script>"] [severity "critical"] [ver "OWASP_CRS/4.31.0-dev"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-xss"] [tag "xss-perf-disable"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "OWASP_CRS/ATTACK-XSS"] [tag "capec/1000/152/242"] [hostname "172.18.0.2"] [uri "/q=%3Cscript%3Ealert%28%29%3C/script%3E"] [unique_id "0f3db12bb382a1584faca3cc6bf67cfd"]
nginx  | [client "192.168.65.1"] Coraza: Warning. NoScript XSS InjectionChecker: HTML Injection [file "/etc/coraza/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [line "9369"] [id "941160"] [rev ""] [msg "NoScript XSS InjectionChecker: HTML Injection"] [data "Matched Data: <script found within REQUEST_FILENAME: /q=<script>alert()</script>"] [severity "critical"] [ver "OWASP_CRS/4.31.0-dev"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-xss"] [tag "xss-perf-disable"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "OWASP_CRS/ATTACK-XSS"] [tag "capec/1000/152/242"] [hostname "172.18.0.2"] [uri "/q=%3Cscript%3Ealert%28%29%3C/script%3E"] [unique_id "0f3db12bb382a1584faca3cc6bf67cfd"]
nginx  | [client "192.168.65.1"] Coraza: Warning. Javascript method detected [file "/etc/coraza/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [line "9944"] [id "941390"] [rev ""] [msg "Javascript method detected"] [data "Matched Data: alert( found within REQUEST_FILENAME: /q=<script>alert()</script>"] [severity "critical"] [ver "OWASP_CRS/4.31.0-dev"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-nodejs"] [tag "attack-xss"] [tag "xss-perf-disable"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "OWASP_CRS/ATTACK-XSS"] [tag "capec/1000/152/242"] [hostname "172.18.0.2"] [uri "/q=%3Cscript%3Ealert%28%29%3C/script%3E"] [unique_id "0f3db12bb382a1584faca3cc6bf67cfd"]
nginx  | [client "192.168.65.1"] Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 15) [file "/etc/coraza/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "13157"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 15)"] [data ""] [severity "unknown"] [ver "OWASP_CRS/4.31.0-dev"] [maturity "0"] [accuracy "0"] [tag "anomaly-evaluation"] [tag "OWASP_CRS"] [hostname "172.18.0.2"] [uri "/q=%3Cscript%3Ealert%28%29%3C/script%3E"] [unique_id "0f3db12bb382a1584faca3cc6bf67cfd"]
nginx  | 
nginx  | --eGHHtdBBsBCPabGh-Z--
nginx  | 
nginx  | 
```
