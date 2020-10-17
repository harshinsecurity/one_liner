## What is One_liner Project ?

The main goal is to share tips from some well-known bug hunters. Using recon methodology, we can find subdomains, APIs, and tokens that are already exploitable, so we can report them. We wish to influence Onelinetips and explain the commands, for the better understanding of new hunters.

<p align="center">
    <a href="https://twitter.com/xploitprotocol">
      <img src="https://img.shields.io/twitter/follow/xploitprotocol?style=social">
  </a>
  <a href="https://github.com/harsh-kk?tab=followers">
      <img alt="GitHub followers" src="https://img.shields.io/github/followers/harsh-kk?label=Follow&style=social">
  </a>
</p>

## Special thanks

- [@Stokfredrik](https://twitter.com/stokfredrik)
- [@Jhaddix](https://twitter.com/Jhaddix)
- [@pdiscoveryio](https://twitter.com/pdiscoveryio)
- [@TomNomNom](https://twitter.com/TomNomNom)
- [@NahamSec](https://twitter.com/NahamSec)



## Scripts that need to be installed

To run the project, you will need to install the following programs:

- [Anew](https://github.com/tomnomnom/anew)
- [Qsreplace](https://github.com/tomnomnom/qsreplace)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Gospider](https://github.com/jaeles-project/gospider)
- [Github-Search](https://github.com/gwen001/github-search)
- [Amass](https://github.com/OWASP/Amass)
- [Hakrawler](https://github.com/hakluke/hakrawler)
- [Gargs](https://github.com/brentp/gargs)


###  Search Asn Amass

- [Explaining command](https://bit.ly/2EMooDB)

Amass intel will search the organization "PayPal" from a database of ASNs at a faster-than-default rate. It will then take these ASN numbers and scan the complete ASN/IP space for all TLD's in that IP space (paypal.com, paypal.co.id, paypal.me).

```bash
amass intel -org paypal -max-dns-queries 2500 | awk -F, '{print $1}' ORS=',' | sed 's/,$//' | xargs -P3 -I@ -d ',' amass intel -asn @ -max-dns-queries 2500''
```

###  Using chaos search js

- [Explaining command](https://bit.ly/32vfRg7)

Choas is an API by Project Discovery that discovers subdomains. Here we are querying thier API for all known subdoains of "att.com". We are then using httpx to find which of those domains is live and hosts an HTTP or HTTPs site. We then pass those URLs to GoSpider to visit them and crawl them for all links (javascript, endpoints, etc). We then grep to find all the JS files. We pipe this all through anew so we see the output iterativlely (faster) and grep for "(http|https)://att.com" to make sure we dont recieve output for domains that are not "att.com".

```bash
chaos -d att.com | httpx -silent | xargs -I@ -P20 sh -c 'gospider -a -s "@" -d 2' | grep -Eo "(http|https)://[^/"].*.js+" | sed "s#]
```

### Search Subdomain using Gospider

- [Explaining command](https://bit.ly/2QtG9do)

```bash
gospider -d 0 -s "https://site.com" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

### Using gospider to chaos

- [Explaining command](https://bit.ly/2D4vW3W)

```bash
chaos -d paypal.com -bbq -filter-wildcard -http-url | xargs -I@ -P5 sh -c 'gospider -a -s "@" -d 3'
```

### Using recon.dev and gospider crawler subdomains

- [Explaining command](https://bit.ly/32pPRDa)

```bash
curl "https://recon.dev/api/search?key=apiKEY&domain=paypal.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew'
```

### PSQL - search subdomain using cert.sh

- [Explaining command](https://bit.ly/32rMA6e)

```bash
psql -A -F , -f querycrt -h http://crt.sh -p 5432 -U guest certwatch 2>/dev/null | tr ', ' '\n' | grep twitch | anew'
```

### Search subdomains using Github and httpx

- [Github-search](https://github.com/gwen001/github-search) - Using python3 to search subdomains, httpx filter hosts by up status-code response (200)

```python
./github-subdomains.py -t APYKEYGITHUB -d domaintosearch | httpx --title
```

### Search SQLINJECTION using qsreplace search syntax error

- [Explained comand](https://bit.ly/3hxFWS2)

```bash
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```

### Search subdomains using jldc

- [Explained comand](https://bit.ly/2YBlEjm)

```bash
curl -s "https://jldc.me/anubis/subdomains/att.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew
```

### Search subdomains in assetfinder using hakrawler spider to search links in content responses

- [Explained comand](https://bit.ly/3hxRvZw)

```bash
assetfinder -subs-only http://tesla.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | grep "tesla"
```

### Search subdomains in cert.sh

- [Explained comand](https://bit.ly/2QrvMXl)

```bash
curl -s "https://crt.sh/?q=%25.att.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | httpx -title -silent | anew
```

### Search subdomains in cert.sh assetfinder to search in link /.git/HEAD

- [Explained comand](https://bit.ly/3lhFcTH)

```bash
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
```bash
curl -s "https://crt.sh/?q=%25.enjoei.com.br&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | httpx -silent -path /.git/HEAD -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
### Collect js files from hosts up by gospider

- [Explained comand](https://bit.ly/3aWIwyI)

```bash
xargs -P 500 -a pay -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew'
```

### Subdomain search Bufferover resolving domain to httpx

- [Explained comand](https://bit.ly/3lno9j0)

```bash
curl -s https://dns.bufferover.run/dns?q=.sony.com |jq -r .FDNS_A[] | sed -s 's/,/\n/g' | httpx -silent | anew
```

### Using gargs to gospider search with parallel proccess
- [Gargs](https://github.com/brentp/gargs)

- [Explained comand](https://bit.ly/2EHj1FD)

```bash
httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -l domain -timeout 5 -threads 200 --follow-redirects -silent | gargs -p 3 'gospider -m 5 --blacklist pdf -t 2 -c 300 -d 5 -a -s {}' | anew stepOne
```

### Injection xss using qsreplace to urls filter to gospider

- [Explained comand](https://bit.ly/3joryw9)

```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

### Extract URL's to apk

- [Explained comand](https://bit.ly/2QzXwJr)

```bash
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|schemas.android\|google\|goo.gl"
```

### Chaos to Gospider

- [Explained comand](https://bit.ly/3gFJbpB)

```bash
chaos -d att.com -o att -silent | httpx -silent | xargs -P100 -I@ gospider -c 30 -t 15 -d 4 -a -H "x-forwarded-for: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1" -s @
```

### Checking invalid certificate

- [Real script](https://bit.ly/2DhAwMo)
- [Script King](https://bit.ly/34Z0kIH)

```bash
xargs -a domain -P1000 -I@ sh -c 'bash cert.sh @ 2> /dev/null' | grep "EXPIRED" | awk '/domain/{print $5}' | httpx
```

### Using shodan & Nuclei

- [Explained comand](https://bit.ly/3jslKle)

```bash
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```

### Open Redirect test using gf.

- [Explained comand](https://bit.ly/3hL263x)

```bash
echo "domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```

### Using shodan to jaeles "How did I find a critical today? well as i said it was very simple, using shodan and jaeles".

- [Explained comand](https://bit.ly/2QQfY0l)

```bash
shodan domain domain| awk '{print $3}'|  httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @
```
### Using Chaos to jaeles "How did I find a critical today?.

- [Explained comand](https://bit.ly/2YXiK8N)

```bash
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 
```

### Using shodan to jaeles
- [Explained comand](https://bit.ly/2Dkmycu)

```bash
domain="domaintotest";shodan domain $domain | awk -v domain="$domain" '{print $1"."domain}'| httpx -threads 300 | anew shodanHostsUp | xargs -I@ -P3 sh -c 'jaeles -c 300 scan -s jaeles-signatures/ -u @'| anew JaelesShodanHosts 
```

### Search to files using assetfinder and ffuf

- [Explained comand](https://bit.ly/2Go3Ba4)

```bash
assetfinder att.com | sed 's#*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'
```

