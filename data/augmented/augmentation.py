import tldextract
import math

def extract_features(url):
    url = str(url).lower()
    ext = tldextract.extract(url)

    hostname = ext.domain + '.' + ext.suffix if ext.domain else ""
    
    path = ""
    if ext.suffix and ext.suffix in url:
        path = url.split(ext.suffix)[-1]
    elif ext.domain and ext.domain in url:
        # If suffix is empty but domain exists, consider path after domain
        domain_index = url.find(ext.domain)
        path_start_index = domain_index + len(ext.domain)
        path = url[path_start_index:]
    else:
        # Fallback for URLs without clear domain/suffix or other structures
        # Consider everything after scheme and potential hostname part
        scheme_end = url.find('://')
        if scheme_end != -1:
            path_start = url.find('/', scheme_end + 3) # Find first slash after scheme and potential host
            if path_start != -1:
                path = url[path_start:]
            else:
                path = "/" # If no slash after scheme, treat as root
        else: # No scheme, just take the whole thing as path if no domain found
            path = url

    return [
        len(url),                             # URL length
        url.count('.'),
        url.count('-'),
        url.count('_'),
        url.count('/'),
        url.count('@'),
        sum(c.isdigit() for c in url),
        int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),  # IP-based
        int(url.startswith('https')),
        len(ext.subdomain.split('.')) if ext.subdomain else 0,  # subdomains
        len(path),                             # path length
        int(any(w in url for w in ['login','verify','secure','account'])),
        int(any(w in url for w in ['admin','upload','config','shell'])),  # defacement hint
        int(any(w in url for w in ['free','win','bonus','gift'])),        # phishing hint
        url.count('%'),                        # encoding
        int('//' in url[8:]),                  # redirection
    ]
