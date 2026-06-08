"""
PhishGuard-X — Layer 1: Advanced URL Intelligence Engine
84 features: original 56 + homograph + redirect + adversarial + unicode
"""

import re, math, unicodedata, hashlib, itertools
from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter
import numpy as np

# ── Constants ──────────────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    'login','signin','sign-in','verify','secure','update','banking','confirm',
    'password','credential','support','service','official','security','alert',
    'suspended','validate','recover','unlock','limited','access','click','free',
    'winner','prize','urgent','action','required','immediately','expire',
    'verification','authenticate','authorization','reset','reactivate','unusual',
    'billing','invoice','payment','refund','suspend','terminate','account',
]
BRAND_NAMES = [
    'paypal','amazon','apple','microsoft','google','facebook','netflix',
    'instagram','twitter','linkedin','dropbox','adobe','chase','wellsfargo',
    'bankofamerica','citibank','ebay','walmart','target','bestbuy',
    'paytm','hdfc','icici','sbi','axisbank','kotak','stripe','coinbase',
    'binance','robinhood','venmo','zelle','cashapp','steam','discord',
    'whatsapp','telegram','dhl','fedex','ups','usps','irs','hmrc',
]
TRUSTED_OFFICIAL = {
    'google.com','accounts.google.com','mail.google.com','microsoft.com',
    'live.com','outlook.com','microsoftonline.com','apple.com','icloud.com',
    'amazon.com','facebook.com','instagram.com','twitter.com','x.com',
    'netflix.com','linkedin.com','github.com','paypal.com','ebay.com',
    'paytm.com','hdfcbank.com','icicibank.com','sbi.co.in','chase.com',
    'wellsfargo.com','bankofamerica.com','discord.com','telegram.org',
}
SHORTENERS = {
    'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','short.io','tiny.cc',
    'is.gd','rb.gy','buff.ly','adf.ly','bc.vc','j.mp','tr.im',
}
SUSPICIOUS_TLDS = {
    'tk','ml','ga','cf','gq','xyz','top','club','online','site','website',
    'bid','win','stream','download','accountant','date','faith','review',
    'science','trade','webcam','party','cricket','racing','link','kim',
}

# Unicode confusable map (subset of TR#36 for common phishing chars)
LEET_MAP = str.maketrans('01345678@!', 'oieasgtbai')

# Cyrillic → Latin confusables
CYRILLIC_CONFUSABLES = {
    'а':'a','е':'e','о':'o','р':'p','с':'c','у':'y','х':'x',
    'А':'A','В':'B','Е':'E','К':'K','М':'M','Н':'H','О':'O',
    'Р':'P','С':'C','Т':'T','У':'Y','Х':'X',
}

def _extract_tld_parts(netloc: str):
    netloc = netloc.lower().split(':')[0]
    parts  = netloc.split('.')
    if len(parts) == 1: return '', parts[0], ''
    if len(parts) >= 3 and parts[-2] in {'co','com','org','net','gov','edu','ac'}:
        return '.'.join(parts[:-3]), parts[-3] if len(parts)>2 else '', '.'.join(parts[-2:])
    return '.'.join(parts[:-2]), parts[-2], parts[-1]

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

# ── Homograph Detection ────────────────────────────────────────────────────

def detect_script_mixing(domain: str) -> dict:
    """Detect mixed Unicode scripts (Latin+Cyrillic = homograph attack)."""
    scripts = set()
    for ch in domain:
        try:
            name = unicodedata.name(ch, '')
            if 'LATIN' in name:       scripts.add('latin')
            elif 'CYRILLIC' in name:  scripts.add('cyrillic')
            elif 'GREEK' in name:     scripts.add('greek')
            elif 'ARMENIAN' in name:  scripts.add('armenian')
            elif 'ARABIC' in name:    scripts.add('arabic')
            elif 'HEBREW' in name:    scripts.add('hebrew')
            elif 'CJK' in name:       scripts.add('cjk')
        except Exception:
            pass
    mixed = len(scripts) > 1
    return {
        'scripts_detected': list(scripts),
        'is_mixed_script':  int(mixed),
        'script_count':     len(scripts),
    }

def normalize_confusables(domain: str) -> str:
    """Replace Cyrillic confusables with Latin equivalents."""
    result = []
    for ch in domain:
        result.append(CYRILLIC_CONFUSABLES.get(ch, ch))
    return ''.join(result)

def detect_homograph_brand_spoof(domain: str) -> dict:
    """Normalize confusables then check brand match."""
    normalized = normalize_confusables(domain.lower())
    leet_norm  = normalized.translate(LEET_MAP)
    brand_match_cyrillic = any(b in normalized for b in BRAND_NAMES)
    brand_match_leet     = any(b in leet_norm  for b in BRAND_NAMES) and leet_norm != normalized
    punycode_decode = ''
    if domain.startswith('xn--'):
        try:
            punycode_decode = domain.encode('ascii').decode('idna')
        except Exception:
            pass
    return {
        'has_homograph_spoof':   int(brand_match_cyrillic or brand_match_leet),
        'has_cyrillic_spoof':    int(brand_match_cyrillic),
        'has_leet_spoof':        int(brand_match_leet),
        'has_punycode':          int(domain.startswith('xn--')),
        'punycode_decoded_brand':int(any(b in punycode_decode.lower() for b in BRAND_NAMES) if punycode_decode else 0),
    }

def detect_rtl_override(url: str) -> int:
    """Detect Right-To-Left Override character U+202E (visual domain reversal)."""
    return int('\u202e' in url or '\u200b' in url or '\u00ad' in url)

# ── Redirect Chain ─────────────────────────────────────────────────────────

def analyze_redirect_chain(url: str, timeout: int = 5) -> dict:
    """Follow redirects and extract chain metadata (max 8 hops)."""
    try:
        import requests as req
        session = req.Session()
        session.max_redirects = 8
        resp = session.head(url, allow_redirects=True, timeout=timeout,
                            headers={'User-Agent': 'Mozilla/5.0'})
        history = resp.history
        chain   = [r.url for r in history] + [resp.url]
        final   = resp.url
        return {
            'redirect_count':       len(history),
            'redirect_crosses_tld': int(_crosses_tld_boundary(url, final)),
            'chain_contains_shortener': int(any(
                any(s in h.url for s in SHORTENERS) for h in history
            )),
            'final_url_different':  int(url.rstrip('/') != final.rstrip('/')),
        }
    except Exception:
        return {'redirect_count':0,'redirect_crosses_tld':0,
                'chain_contains_shortener':0,'final_url_different':0}

def _crosses_tld_boundary(url1: str, url2: str) -> bool:
    try:
        d1 = urlparse(url1).netloc
        d2 = urlparse(url2).netloc
        _,dom1,suf1 = _extract_tld_parts(d1)
        _,dom2,suf2 = _extract_tld_parts(d2)
        return (dom1+'.'+suf1) != (dom2+'.'+suf2)
    except Exception:
        return False

# ── Obfuscation Detection ──────────────────────────────────────────────────

def detect_obfuscation(url: str, query: str) -> dict:
    import base64
    b64_in_params = 0
    for val in parse_qs(query).values():
        for v in val:
            try:
                decoded = base64.b64decode(v + '==').decode('utf-8', errors='ignore')
                if 'http' in decoded.lower(): b64_in_params = 1
            except Exception:
                pass
    hex_ip = int(bool(re.search(r'0x[0-9a-fA-F]{8}', url)))
    octal_ip = int(bool(re.search(r'\b0[0-7]+\.[0-7]+\.[0-7]+\.[0-7]+\b', url)))
    return {
        'has_base64_redirect':  b64_in_params,
        'has_hex_ip':           hex_ip,
        'has_octal_ip':         octal_ip,
        'has_data_uri':         int('data:' in url.lower()),
        'has_javascript_uri':   int('javascript:' in url.lower()),
    }

# ── Main Feature Extractor ─────────────────────────────────────────────────

def extract_url_features(url: str, follow_redirects: bool = False) -> dict:
    """Extract all 84 URL intelligence features."""
    if not url.startswith(('http://','https://')):
        url = 'http://' + url

    try:
        parsed  = urlparse(url)
    except Exception:
        return {k: 0 for k in get_feature_names()}

    netloc   = parsed.netloc.lower()
    path     = parsed.path.lower()
    query    = parsed.query.lower()
    fragment = parsed.fragment.lower()
    sub, dom, suf = _extract_tld_parts(netloc)
    url_lower     = url.lower()
    domain_lower  = dom.lower()
    full_netloc   = netloc

    # ── Trusted domain bypass ──────────────────────────────────────────────
    is_trusted = int(full_netloc in TRUSTED_OFFICIAL or
                     domain_lower+'.'+suf in TRUSTED_OFFICIAL)

    f = {}

    # GROUP 1: Length
    f['url_length']      = len(url)
    f['domain_length']   = len(full_netloc)
    f['path_length']     = len(path)
    f['query_length']    = len(query)
    f['hostname_length'] = len(parsed.hostname or '')

    # GROUP 2: Character stats
    f['count_dots']        = url.count('.')
    f['count_hyphens']     = url.count('-')
    f['count_underscores'] = url.count('_')
    f['count_slashes']     = url.count('/')
    f['count_at_signs']    = url.count('@')
    f['count_percent']     = url.count('%')
    f['count_equals']      = url.count('=')
    f['count_ampersand']   = url.count('&')
    f['count_digits_url']  = sum(c.isdigit() for c in url)
    f['count_digits_dom']  = sum(c.isdigit() for c in full_netloc)
    f['ratio_digits_url']  = f['count_digits_url'] / max(len(url), 1)
    f['ratio_digits_dom']  = f['count_digits_dom'] / max(len(full_netloc), 1)
    f['special_char_count']= len(re.findall(r'[^a-zA-Z0-9]', url))

    # GROUP 3: Entropy
    f['url_entropy']       = shannon_entropy(url)
    f['domain_entropy']    = shannon_entropy(full_netloc)
    f['path_entropy']      = shannon_entropy(path)
    f['subdomain_entropy'] = shannon_entropy(sub)

    # GROUP 4: Structural
    f['has_https']         = int(parsed.scheme == 'https')
    f['has_ip']            = int(bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', full_netloc)))
    f['has_at_sign']       = int('@' in url)
    f['has_double_slash']  = int('//' in path)
    f['has_port']          = int(parsed.port is not None)
    f['port_number']       = parsed.port or 0
    f['subdomain_count']   = len(sub.split('.')) if sub else 0
    f['path_depth']        = len([p for p in path.split('/') if p])
    f['query_param_count'] = len(parse_qs(parsed.query))

    # GROUP 5: Domain
    f['tld_length']            = len(suf)
    f['is_suspicious_tld']     = int(suf in SUSPICIOUS_TLDS)
    f['has_www']               = int(sub == 'www')
    f['domain_hyphen_count']   = domain_lower.count('-')
    f['subdomain_hyphen_count']= sub.count('-')

    # GROUP 6: Keywords (trusted domains suppress)
    domain_path = full_netloc + path
    raw_kw = sum(kw in domain_path for kw in SUSPICIOUS_KEYWORDS)
    f['suspicious_keyword_count'] = 0 if is_trusted else raw_kw
    f['has_login_keyword']    = int(not is_trusted and any(k in domain_path for k in ['login','signin','sign-in']))
    f['has_security_keyword'] = int(not is_trusted and any(k in domain_path for k in ['secure','security','verify','validate']))
    f['has_financial_keyword']= int(not is_trusted and any(k in domain_path for k in ['bank','payment','credit','billing','invoice']))

    # GROUP 7: Brand
    brand_in_sub  = any(b in sub for b in BRAND_NAMES)
    brand_is_own  = any(b == domain_lower for b in BRAND_NAMES)
    brand_in_dom  = any(b in domain_lower for b in BRAND_NAMES)
    f['brand_name_in_subdomain'] = int(brand_in_sub and not brand_is_own)
    f['brand_name_in_domain']    = int(brand_in_dom and not brand_is_own and not is_trusted)
    f['brand_name_in_path']      = int(not brand_is_own and any(b in path for b in BRAND_NAMES))
    f['is_trusted_official']     = is_trusted

    # GROUP 8: Redirect/Obfuscation
    f['has_url_shortener']   = int(any(s in url_lower for s in SHORTENERS))
    f['has_encoded_chars']   = int('%' in url and bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    f['double_encoded']      = int(bool(re.search(r'%25[0-9a-fA-F]{2}', url)))
    f['has_redirect_param']  = int(any(p in query for p in ['redirect','return','url=','goto','next=']))

    # GROUP 9: Lexical
    f['max_repeated_char']   = max((len(list(g)) for _,g in itertools.groupby(url)), default=0)
    vowels = sum(c in 'aeiou' for c in full_netloc)
    cons   = sum(c.isalpha() and c not in 'aeiou' for c in full_netloc)
    f['vowel_ratio']         = vowels / max(vowels+cons, 1)
    words  = re.split(r'[\.\-_]', domain_lower)
    f['longest_word_domain'] = max((len(w) for w in words), default=0)

    # GROUP 10: Homograph/Unicode (NEW)
    hg = detect_homograph_brand_spoof(domain_lower)
    f.update(hg)
    sm = detect_script_mixing(full_netloc)
    f['is_mixed_script']     = sm['is_mixed_script']
    f['script_count']        = sm['script_count']
    f['has_rtl_override']    = detect_rtl_override(url)

    # GROUP 11: Leet brand spoof (NEW)
    leet_norm = domain_lower.translate(LEET_MAP)
    f['has_leet_brand_spoof']= int(any(b in leet_norm for b in BRAND_NAMES) and leet_norm != domain_lower)

    # GROUP 12: Obfuscation (NEW)
    obs = detect_obfuscation(url, query)
    f.update(obs)

    # GROUP 13: Composite risk meta-feature
    risk = 0
    risk += f['has_ip']                   * 3.5
    risk += f['has_at_sign']              * 3.0
    risk += f['brand_name_in_subdomain']  * 3.5
    risk += f['brand_name_in_domain']     * 3.0
    risk += f['has_homograph_spoof']      * 4.0
    risk += f['has_leet_brand_spoof']     * 3.5
    risk += f['double_encoded']           * 2.5
    risk += f['has_url_shortener']        * 2.5
    risk += f['is_suspicious_tld']        * 1.8
    risk += min(f['suspicious_keyword_count'] * 0.7, 2.5)
    risk += f['has_redirect_param']       * 1.5
    risk += min(f['subdomain_count'] * 0.5, 1.5)
    risk += f['domain_hyphen_count']      * 0.6
    risk += f['has_leet_brand_spoof']     * 1.0
    risk += f['has_port']                 * 0.9
    risk += (1 - f['has_https'])          * 0.9
    risk += f['has_encoded_chars']        * 0.6
    risk += min(f['url_length'] / 120, 0.8)
    risk += f['is_mixed_script']          * 2.0
    f['heuristic_risk_score'] = min(risk / 20.0 * 10, 10)

    # Redirect chain (optional — network call)
    if follow_redirects:
        rd = analyze_redirect_chain(url)
        f.update(rd)
    else:
        f['redirect_count'] = 0
        f['redirect_crosses_tld'] = 0
        f['chain_contains_shortener'] = 0
        f['final_url_different'] = 0

    return f

def get_feature_names() -> list:
    return list(extract_url_features("http://example.com").keys())

def extract_feature_vector(url: str, follow_redirects: bool = False) -> np.ndarray:
    f = extract_url_features(url, follow_redirects)
    return np.array([f.get(k, 0) for k in get_feature_names()], dtype=np.float64)

def batch_extract(urls: list, follow_redirects: bool = False) -> np.ndarray:
    return np.array([extract_feature_vector(u, follow_redirects) for u in urls])
