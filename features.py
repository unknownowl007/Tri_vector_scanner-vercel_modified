import re


def extract_features(url):
    url = str(url).lower()
    brands = [
        "google",
        "facebook",
        "microsoft",
        "amazon",
        "apple",
        "netflix",
        "instagram",
        "paypal",
        "ebay",
        "walmart",
        "outlook",
    ]

    dots = url.count('.')
    subdomains = dots - 1 if dots > 1 else 0

    return [
        len(url),
        dots,
        url.count('-'),
        url.count('/'),
        url.count('@'),
        url.count('?'),
        url.count('_') + url.count('%'),
        subdomains,
        1 if "//" in url[7:] else 0,
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        1 if url.startswith('https') else 0,
        sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        1 if any(word in url for word in [
            'login',
            'verify',
            'bank',
            'secure',
            'update',
            'support',
            'service',
        ]) else 0,
        1 if any(brand in url for brand in brands) else 0,
        1 if any(url.endswith(ext) for ext in ['.php', '.html', '.aspx', '.exe']) else 0,
    ]
