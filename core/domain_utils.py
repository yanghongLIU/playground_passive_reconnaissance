from urllib.parse import urlparse

import tldextract


def extract_domain(url_or_domain: str) -> dict:
    raw = url_or_domain.strip()

    # tldextract handles bare domains fine, but urlparse needs a scheme to
    # distinguish host from path when there is no "//".
    if "://" not in raw:
        parse_target = "https://" + raw
    else:
        parse_target = raw

    parsed = urlparse(parse_target)
    # netloc may include port; strip it for extraction
    host = parsed.hostname or parsed.netloc.split(":")[0]

    ext = tldextract.extract(host)

    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host

    return {
        "input": url_or_domain,
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "registered_domain": registered_domain,
    }
