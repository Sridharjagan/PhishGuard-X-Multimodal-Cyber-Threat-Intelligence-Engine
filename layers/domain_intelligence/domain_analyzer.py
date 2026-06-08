"""
PhishGuard-X — Layer 2: Domain Intelligence
WHOIS + DNS + SSL + Registrar Reputation scoring
"""

import re, json, time, socket, hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
import numpy as np

# High-risk registrar patterns (historically elevated abuse rates)
HIGH_RISK_REGISTRARS = {
    'namecheap','godaddy','pdr','publicdomainregistry','reg.ru','internet.bs',
    'epik','alibaba','west263','bizcn','ename','net.cn',
}
SUSPICIOUS_NAMESERVERS = {
    'afraid.org','changeip.com','no-ip.com','dyndns.org','dynalias.com',
    'ddns.net','serveblog.net','redirectme.net','mooo.com',
}

def _safe_whois(domain: str) -> dict:
    """WHOIS lookup with graceful fallback."""
    try:
        import whois
        w = whois.whois(domain)
        return {
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'registrar': str(w.registrar or '').lower(),
            'name_servers': [str(ns).lower() for ns in (w.name_servers or [])],
            'status': str(w.status or ''),
            'country': str(w.country or ''),
            'dnssec': str(w.dnssec or ''),
        }
    except Exception:
        return {}

def _compute_domain_age_days(creation_date) -> int:
    """Return domain age in days from creation_date (handles list or datetime)."""
    try:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -1
        if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.utcnow()
            if hasattr(creation_date, 'tzinfo'):
                creation_date = creation_date.replace(tzinfo=None)
        return (now - creation_date).days if hasattr(now-creation_date,'days') else -1
    except Exception:
        return -1

def _safe_dns(domain: str) -> dict:
    """DNS record inspection."""
    result = {
        'has_mx_record': 0, 'has_spf': 0, 'has_dmarc': 0,
        'dns_ttl': -1, 'ns_count': 0, 'has_suspicious_ns': 0,
        'ip_count': 0, 'resolves': 0,
    }
    try:
        import dns.resolver
        # A record
        try:
            a = dns.resolver.resolve(domain, 'A')
            result['resolves'] = 1
            result['ip_count'] = len(list(a))
            result['dns_ttl'] = a.rrset.ttl if a.rrset else -1
        except Exception:
            pass
        # MX
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            result['has_mx_record'] = 1
        except Exception:
            pass
        # TXT (SPF + DMARC)
        try:
            txt = dns.resolver.resolve(domain, 'TXT')
            for t in txt:
                s = str(t).lower()
                if 'v=spf1' in s: result['has_spf'] = 1
        except Exception:
            pass
        try:
            dmarc = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
            result['has_dmarc'] = 1
        except Exception:
            pass
        # NS
        try:
            ns = dns.resolver.resolve(domain, 'NS')
            ns_list = [str(n).lower() for n in ns]
            result['ns_count'] = len(ns_list)
            result['has_suspicious_ns'] = int(any(
                any(sus in n for sus in SUSPICIOUS_NAMESERVERS) for n in ns_list
            ))
        except Exception:
            pass
    except ImportError:
        # fallback: socket-based A record only
        try:
            socket.getaddrinfo(domain, None)
            result['resolves'] = 1
        except Exception:
            pass
    return result

def _safe_ssl(domain: str) -> dict:
    """SSL certificate inspection."""
    result = {
        'has_ssl': 0, 'ssl_days_valid': -1, 'ssl_issuer_risk': 0,
        'ssl_self_signed': 0, 'ssl_wildcard': 0, 'ssl_san_count': 0,
    }
    try:
        import ssl, socket
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            result['has_ssl'] = 1
            # Expiry
            exp = ssl.cert_time_to_seconds(cert.get('notAfter',''))
            result['ssl_days_valid'] = max(0, int((exp - time.time()) / 86400))
            # Issuer
            issuer = dict(x[0] for x in cert.get('issuer', []))
            org = issuer.get('organizationName', '').lower()
            result['ssl_self_signed'] = int(issuer == dict(x[0] for x in cert.get('subject',[])))
            result['ssl_issuer_risk'] = int(
                "let's encrypt" in org or "zerossl" in org or "buypass" in org
            )
            # SANs
            sans = cert.get('subjectAltName', [])
            result['ssl_san_count'] = len(sans)
            result['ssl_wildcard'] = int(any('*' in s[1] for s in sans if s[0]=='DNS'))
    except Exception:
        pass
    return result

def analyze_domain(url: str, timeout: int = 8) -> dict:
    """Full domain intelligence analysis. Returns feature dict."""
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://'+url)
        netloc = parsed.hostname or ''
        # Strip www
        domain = re.sub(r'^www\.', '', netloc)
    except Exception:
        domain = ''

    features = {}

    # ── WHOIS ──────────────────────────────────────────────────
    w = _safe_whois(domain)
    age = _compute_domain_age_days(w.get('creation_date'))
    features['domain_age_days']   = max(age, 0) if age >= 0 else 0
    features['domain_age_risk']   = round(min(1.0, 1.0 / (1 + age/30)) if age >= 0 else 0.9, 4)
    features['domain_very_new']   = int(0 <= age <= 7)
    features['domain_new']        = int(0 <= age <= 30)
    # Registrar risk
    reg = w.get('registrar','')
    features['high_risk_registrar']= int(any(h in reg for h in HIGH_RISK_REGISTRARS))
    features['whois_available']    = int(bool(w))
    features['dnssec_enabled']     = int('signed' in w.get('dnssec','').lower())
    features['registrar_country_risk'] = int(w.get('country','').upper() in
        {'CN','RU','UA','NG','KP','IR','PK'})

    # ── DNS ────────────────────────────────────────────────────
    dns_data = _safe_dns(domain)
    features.update({
        'has_mx_record':     dns_data['has_mx_record'],
        'has_spf':           dns_data['has_spf'],
        'has_dmarc':         dns_data['has_dmarc'],
        'dns_ttl':           dns_data['dns_ttl'],
        'ns_count':          dns_data['ns_count'],
        'has_suspicious_ns': dns_data['has_suspicious_ns'],
        'ip_count':          dns_data['ip_count'],
        'domain_resolves':   dns_data['resolves'],
        'fast_flux_risk':    int(dns_data['dns_ttl'] >= 0 and dns_data['dns_ttl'] < 300),
    })

    # ── SSL ────────────────────────────────────────────────────
    ssl_data = _safe_ssl(domain)
    features.update({
        'has_ssl':          ssl_data['has_ssl'],
        'ssl_days_valid':   ssl_data['ssl_days_valid'],
        'ssl_issuer_risk':  ssl_data['ssl_issuer_risk'],
        'ssl_self_signed':  ssl_data['ssl_self_signed'],
        'ssl_wildcard':     ssl_data['ssl_wildcard'],
        'ssl_san_count':    ssl_data['ssl_san_count'],
        'ssl_fresh_cert':   int(0 <= ssl_data['ssl_days_valid'] <= 90),
    })

    # ── Composite domain risk ──────────────────────────────────
    dr = 0
    dr += features['domain_age_risk'] * 3.0
    dr += features['high_risk_registrar'] * 1.5
    dr += features['has_suspicious_ns'] * 2.0
    dr += features['fast_flux_risk'] * 2.0
    dr += features['ssl_issuer_risk'] * 0.5
    dr += features['ssl_self_signed'] * 1.5
    dr += (1 - features['has_mx_record']) * 0.5
    dr += (1 - features['has_spf']) * 0.5
    dr += (1 - features['has_dmarc']) * 0.5
    dr += features['registrar_country_risk'] * 1.0
    features['domain_risk_score'] = round(min(dr / 10.0 * 10, 10), 2)

    return features

def get_domain_feature_names() -> list:
    return list(analyze_domain("http://example.com").keys())
