import pandas as pd
import re
from pathlib import Path
from urllib.parse import urlparse

original_path = Path('datasets/Training.csv')
new_path = Path('newtrainigndta.csv')

if not original_path.exists():
    raise FileNotFoundError(f'Original training file not found: {original_path}')

if not new_path.exists():
    raise FileNotFoundError(f'New training file not found: {new_path}')

# Load the original training data.
df_original = pd.read_csv(original_path)

# The additional URL file has no header row.
df_new = pd.read_csv(new_path, header=None, names=['url'])

def normalize_url(url):
    url = str(url).strip()
    if not url:
        return url
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = 'http://' + url
    return url


def split_words(text):
    return re.findall(r'[A-Za-z0-9]+', text)


def max_consecutive_repeats(text):
    return max((len(match.group(0)) for match in re.finditer(r'(.)\\1*', text)), default=0)


KNOWN_SHORTENERS = {
    'bit.ly',
    'tinyurl.com',
    't.co',
    'goo.gl',
    'ow.ly',
    'buff.ly',
    'adf.ly',
    'bit.do',
    'cutt.ly',
    'is.gd',
    'shorturl.at',
}

PHISH_KEYWORDS = [
    'login',
    'signin',
    'verify',
    'bank',
    'secure',
    'update',
    'support',
    'service',
    'account',
    'confirm',
    'password',
]

BRAND_KEYWORDS = [
    'google',
    'facebook',
    'microsoft',
    'amazon',
    'apple',
    'netflix',
    'instagram',
    'paypal',
    'ebay',
    'walmart',
    'outlook',
]

SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'country', 'stream', 'download'}

KNOWN_TLDS = {
    'com', 'net', 'org', 'info', 'biz', 'gov', 'edu', 'co', 'io', 'ru', 'cn',
    'uk', 'de', 'jp', 'fr', 'br', 'au', 'us', 'ca',
}


def derive_url_features(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path or ''
    query = parsed.query or ''
    fragment = parsed.fragment or ''
    path_full = path + ('?' + query if query else '') + ('#' + fragment if fragment else '')
    full_url = url
    host_only = host.split('@')[-1]
    host_parts = [part for part in host_only.split('.') if part]
    tld = host_parts[-1] if len(host_parts) > 1 else ''
    subdomains = max(0, len(host_parts) - 2)
    words_raw = split_words(full_url)
    words_host = split_words(host_only)
    words_path = split_words(path_full)
    digits_url = sum(1 for c in full_url if c.isdigit())
    digits_host = sum(1 for c in host_only if c.isdigit())

    return {
        'length_url': len(full_url),
        'length_hostname': len(host_only),
        'ip': 1 if re.search(r'\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b', host_only) else 0,
        'nb_dots': full_url.count('.'),
        'nb_hyphens': full_url.count('-'),
        'nb_at': full_url.count('@'),
        'nb_qm': full_url.count('?'),
        'nb_and': full_url.count('&'),
        'nb_or': full_url.count('|'),
        'nb_eq': full_url.count('='),
        'nb_underscore': full_url.count('_'),
        'nb_tilde': full_url.count('~'),
        'nb_percent': full_url.count('%'),
        'nb_slash': full_url.count('/'),
        'nb_star': full_url.count('*'),
        'nb_colon': full_url.count(':'),
        'nb_comma': full_url.count(','),
        'nb_semicolumn': full_url.count(';'),
        'nb_dollar': full_url.count('$'),
        'nb_space': full_url.count(' '),
        'nb_www': full_url.count('www'),
        'nb_com': full_url.count('.com'),
        'nb_dslash': max(0, full_url.count('//') - 1),
        'http_in_path': 1 if re.search(r'https?://', path_full) else 0,
        'https_token': 1 if full_url.startswith('https') else 0,
        'ratio_digits_url': digits_url / len(full_url) if full_url else 0,
        'ratio_digits_host': digits_host / len(host_only) if host_only else 0,
        'punycode': 1 if 'xn--' in host_only else 0,
        'port': parsed.port or 0,
        'tld_in_path': 1 if re.search(r'\\.(?:' + '|'.join(re.escape(t) for t in KNOWN_TLDS) + r')(?:$|[/?#])', path_full) else 0,
        'tld_in_subdomain': 1 if any(part in KNOWN_TLDS for part in host_parts[:-2]) else 0,
        'abnormal_subdomain': 1 if subdomains > 2 or any(len(part) > 15 for part in host_parts[:-2]) else 0,
        'nb_subdomains': subdomains,
        'prefix_suffix': 1 if '-' in host_only else 0,
        'random_domain': 1 if len(host_only) > 25 and re.search(r'\\d', host_only) else 0,
        'shortening_service': 1 if any(short in host_only for short in KNOWN_SHORTENERS) else 0,
        'path_extension': 1 if re.search(r'\\.(php|html|aspx|exe|jsp|asp|cfm|pl|cgi)(?:$|[/?#])', path_full) else 0,
        'nb_redirection': max(0, full_url.count('//') - 1),
        'length_words_raw': sum(len(w) for w in words_raw),
        'char_repeat': max_consecutive_repeats(full_url),
        'shortest_words_raw': min((len(w) for w in words_raw), default=0),
        'shortest_word_host': min((len(w) for w in words_host), default=0),
        'shortest_word_path': min((len(w) for w in words_path), default=0),
        'longest_words_raw': max((len(w) for w in words_raw), default=0),
        'longest_word_host': max((len(w) for w in words_host), default=0),
        'longest_word_path': max((len(w) for w in words_path), default=0),
        'avg_words_raw': (sum(len(w) for w in words_raw) / len(words_raw)) if words_raw else 0,
        'avg_word_host': (sum(len(w) for w in words_host) / len(words_host)) if words_host else 0,
        'avg_word_path': (sum(len(w) for w in words_path) / len(words_path)) if words_path else 0,
        'phish_hints': 1 if any(keyword in full_url for keyword in PHISH_KEYWORDS) else 0,
        'domain_in_brand': 1 if any(keyword in host_only for keyword in BRAND_KEYWORDS) else 0,
        'brand_in_subdomain': 1 if any(keyword in part for keyword in BRAND_KEYWORDS for part in host_parts[:-2]) else 0,
        'brand_in_path': 1 if any(keyword in path_full for keyword in BRAND_KEYWORDS) else 0,
        'suspecious_tld': 1 if tld in SUSPICIOUS_TLDS else 0,
        'statistical_report': 0,
        'nb_hyperlinks': 0,
        'ratio_intHyperlinks': 0.0,
        'ratio_extHyperlinks': 0.0,
        'ratio_nullHyperlinks': 0.0,
        'nb_extCSS': 0,
        'ratio_intRedirection': 0.0,
        'ratio_extRedirection': 0.0,
        'ratio_intErrors': 0.0,
        'ratio_extErrors': 0.0,
        'login_form': 1 if any(keyword in full_url for keyword in ['login', 'signin', 'submit', 'auth', 'verify']) else 0,
        'external_favicon': 0,
        'links_in_tags': 0,
        'submit_email': 0,
        'ratio_intMedia': 0.0,
        'ratio_extMedia': 0.0,
        'sfh': 0,
        'iframe': 0,
        'popup_window': 0,
        'safe_anchor': 0,
        'onmouseover': 0,
        'right_clic': 0,
        'empty_title': 0,
        'domain_in_title': 0,
        'domain_with_copyright': 0,
        'whois_registered_domain': 0,
        'domain_registration_length': -1,
        'domain_age': -1,
        'web_traffic': 0,
        'dns_record': 0,
        'google_index': 0,
        'page_rank': 0,
    }


# Derive the URL-based features for each new row.
feature_rows = [derive_url_features(url) for url in df_new['url']]
feature_df = pd.DataFrame(feature_rows)

df_new = pd.concat([df_new.reset_index(drop=True), feature_df.reset_index(drop=True)], axis=1)

df_new['status'] = 'phishing'

missing_columns = [col for col in df_original.columns if col not in df_new.columns]
if missing_columns:
    print('Warning: new data is missing these columns:', missing_columns)
    print('These columns cannot be derived from the URL alone and will remain NaN.')

# Match the original column order before combining the datasets.
df_new = df_new.reindex(columns=df_original.columns)

# Append the new phishing URLs to the original training data.
df_combined = pd.concat([df_original, df_new], ignore_index=True)

df_combined.to_csv(original_path, index=False)

print(f'Success! Training data expanded to {df_combined.shape[0]} rows.')
