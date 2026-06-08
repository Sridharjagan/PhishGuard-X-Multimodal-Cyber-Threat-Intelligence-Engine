"""
PhishGuard-X — Layer 3: Website Content Intelligence
HTML + Form + JS analysis (requests-based, no Playwright dependency)
"""

import re, json, hashlib
from urllib.parse import urlparse, urljoin
import numpy as np

try:
    import requests as req
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# Credential harvesting form targets
CREDENTIAL_FORM_KEYWORDS = [
    'password','passwd','pwd','pass','login','username','userid','email',
    'credential','account','card','cvv','ssn','pin','token','secret',
]
SUSPICIOUS_FORM_ACTIONS = ['data:', 'javascript:', 'mailto:']
OBFUSCATION_PATTERNS = [
    r'eval\s*\(',           # eval() execution
    r'unescape\s*\(',       # character unescaping
    r'String\.fromCharCode', # character code array
    r'atob\s*\(',           # base64 decode
    r'\\x[0-9a-fA-F]{2}',  # hex escape sequences
    r'\\u[0-9a-fA-F]{4}',  # unicode escape sequences
    r'document\.write\s*\(', # DOM injection
    r'window\[',            # bracket notation (anti-analysis)
]
SOCIAL_ENG_PATTERNS = {
    'urgency':    [r'act\s+now',r'limited\s+time',r'expires?\s+in',r'urgent',r'immediately',r'warning'],
    'fear':       [r'suspend',r'blocked',r'unauthorized',r'compromised',r'risk',r'threat'],
    'authority':  [r'official\s+notice',r'government',r'irs',r'bank\s+notification',r'security\s+team'],
    'reward':     [r'you\s+have\s+won',r'congratulations',r'prize',r'reward',r'gift\s+card'],
}

def _fetch_page(url: str, timeout: int = 8) -> tuple:
    """Fetch page HTML with error handling. Returns (html, status_code, final_url)."""
    if not HAS_BS4:
        return '', 0, url
    try:
        r = req.get(url, timeout=timeout, verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'},
                    allow_redirects=True, stream=False)
        return r.text[:500_000], r.status_code, r.url  # cap at 500KB
    except Exception:
        return '', 0, url

def analyze_html_structure(html: str, base_url: str) -> dict:
    """Analyze HTML structure for phishing indicators."""
    if not html or not HAS_BS4:
        return {k: 0 for k in [
            'has_password_input','has_hidden_inputs','suspicious_form_action',
            'external_form_target','form_count','input_count',
            'has_meta_refresh','favicon_mismatch','title_brand_mismatch',
            'has_iframe','has_onclick_redirect',
        ]}

    soup = BeautifulSoup(html, 'html.parser')
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc

    # Forms
    forms = soup.find_all('form')
    form_count = len(forms)
    has_password = 0
    has_hidden   = 0
    suspicious_action = 0
    external_target   = 0

    for form in forms:
        inputs = form.find_all('input')
        for inp in inputs:
            t = (inp.get('type','') or '').lower()
            n = (inp.get('name','') or inp.get('id','')).lower()
            if t == 'password': has_password = 1
            if t == 'hidden': has_hidden = 1
            if any(kw in n for kw in CREDENTIAL_FORM_KEYWORDS): has_password = 1

        action = (form.get('action') or '').lower()
        if any(a in action for a in SUSPICIOUS_FORM_ACTIONS):
            suspicious_action = 1
        if action.startswith('http') and base_domain and base_domain not in action:
            external_target = 1

    # Meta refresh
    meta = soup.find('meta', attrs={'http-equiv': re.compile('refresh', re.I)})
    has_meta_refresh = int(bool(meta))

    # Favicon mismatch
    favicon_mismatch = 0
    fav = soup.find('link', rel=re.compile('icon', re.I))
    if fav and fav.get('href'):
        fav_url = urljoin(base_url, fav['href'])
        fav_domain = urlparse(fav_url).netloc
        if fav_domain and base_domain and fav_domain != base_domain:
            favicon_mismatch = 1

    # Title brand mismatch
    title_brand_mismatch = 0
    title = soup.find('title')
    if title and title.text:
        title_lower = title.text.lower()
        from layers.url_intelligence.feature_engine import BRAND_NAMES
        title_has_brand  = any(b in title_lower for b in BRAND_NAMES)
        domain_has_brand = any(b in base_domain.lower() for b in BRAND_NAMES)
        title_brand_mismatch = int(title_has_brand and not domain_has_brand)

    iframes = soup.find_all('iframe')
    onclick_redirects = soup.find_all(onclick=re.compile(r'location\s*\.', re.I))

    return {
        'has_password_input':    has_password,
        'has_hidden_inputs':     has_hidden,
        'suspicious_form_action':suspicious_action,
        'external_form_target':  external_target,
        'form_count':            form_count,
        'input_count':           len(soup.find_all('input')),
        'has_meta_refresh':      has_meta_refresh,
        'favicon_mismatch':      favicon_mismatch,
        'title_brand_mismatch':  title_brand_mismatch,
        'has_iframe':            int(len(iframes) > 0),
        'has_onclick_redirect':  int(len(onclick_redirects) > 0),
    }

def analyze_javascript(html: str) -> dict:
    """Static JavaScript obfuscation analysis."""
    if not html:
        return {k: 0 for k in [
            'js_eval_count','js_obfuscation_score','js_has_fromcharcode',
            'js_has_atob','js_has_document_write','js_suspicious_patterns',
        ]}

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    js_text = '\n'.join(scripts)

    eval_count = len(re.findall(r'\beval\s*\(', js_text))
    obf_score  = 0
    triggered  = 0
    for pat in OBFUSCATION_PATTERNS:
        if re.search(pat, js_text):
            obf_score += 1
            triggered += 1

    return {
        'js_eval_count':            eval_count,
        'js_obfuscation_score':     min(obf_score, 8),
        'js_has_fromcharcode':      int(bool(re.search(r'String\.fromCharCode', js_text))),
        'js_has_atob':              int(bool(re.search(r'\batob\s*\(', js_text))),
        'js_has_document_write':    int(bool(re.search(r'document\.write\s*\(', js_text))),
        'js_suspicious_patterns':   triggered,
    }

def analyze_social_engineering_text(html: str) -> dict:
    """Detect social engineering language patterns in page text."""
    if not html:
        return {f'se_{k}_score': 0 for k in SOCIAL_ENG_PATTERNS}

    if HAS_BS4:
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text(' ', strip=True).lower()
    else:
        text = re.sub(r'<[^>]+>', ' ', html).lower()

    scores = {}
    for category, patterns in SOCIAL_ENG_PATTERNS.items():
        score = sum(1 for p in patterns if re.search(p, text))
        scores[f'se_{category}_score'] = min(score, 5)

    scores['se_total_score'] = sum(scores.values())
    return scores

def analyze_content(url: str) -> dict:
    """Full content intelligence analysis."""
    html, status_code, final_url = _fetch_page(url)

    content_features = {
        'content_fetch_success': int(status_code == 200),
        'status_code':           status_code,
        'page_length':           len(html),
        'redirect_on_fetch':     int(final_url.rstrip('/') != url.rstrip('/')),
    }

    html_feats = analyze_html_structure(html, final_url)
    js_feats   = analyze_javascript(html)
    se_feats   = analyze_social_engineering_text(html)

    content_features.update(html_feats)
    content_features.update(js_feats)
    content_features.update(se_feats)

    # Composite content risk score
    cr = 0
    cr += html_feats['has_password_input']     * 3.0
    cr += html_feats['external_form_target']   * 3.5
    cr += html_feats['suspicious_form_action'] * 2.5
    cr += html_feats['title_brand_mismatch']   * 2.0
    cr += html_feats['favicon_mismatch']       * 1.5
    cr += html_feats['has_meta_refresh']       * 1.0
    cr += js_feats['js_eval_count']            * 0.5
    cr += js_feats['js_obfuscation_score']     * 0.5
    cr += se_feats['se_total_score']           * 0.3
    content_features['content_risk_score'] = round(min(cr / 12.0 * 10, 10), 2)

    return content_features

def get_content_feature_names() -> list:
    return [
        'content_fetch_success','status_code','page_length','redirect_on_fetch',
        'has_password_input','has_hidden_inputs','suspicious_form_action',
        'external_form_target','form_count','input_count','has_meta_refresh',
        'favicon_mismatch','title_brand_mismatch','has_iframe','has_onclick_redirect',
        'js_eval_count','js_obfuscation_score','js_has_fromcharcode','js_has_atob',
        'js_has_document_write','js_suspicious_patterns',
        'se_urgency_score','se_fear_score','se_authority_score','se_reward_score',
        'se_total_score','content_risk_score',
    ]
