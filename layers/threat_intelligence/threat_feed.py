"""
PhishGuard-X — Layer 6: Threat Intelligence Feed Integration
OpenPhish + PhishTank + URLhaus + in-memory cache
"""

import json, time, hashlib, re
from datetime import datetime, timedelta
from urllib.parse import urlparse
import threading

try:
    import requests as req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

class ThreatFeedCache:
    """Thread-safe in-memory threat indicator cache with TTL."""
    def __init__(self, ttl_seconds: int = 3600):
        self._store   = {}
        self._lock    = threading.Lock()
        self._ttl     = ttl_seconds
        self._stats   = {'hits': 0, 'misses': 0, 'total': 0}

    def _key(self, indicator: str) -> str:
        return hashlib.sha256(indicator.lower().encode()).hexdigest()

    def set(self, indicator: str, data: dict):
        k = self._key(indicator)
        with self._lock:
            self._store[k] = {'data': data, 'expires': time.time() + self._ttl}
            self._stats['total'] += 1

    def get(self, indicator: str) -> dict | None:
        k = self._key(indicator)
        with self._lock:
            entry = self._store.get(k)
            if not entry:
                self._stats['misses'] += 1
                return None
            if time.time() > entry['expires']:
                del self._store[k]
                self._stats['misses'] += 1
                return None
            self._stats['hits'] += 1
            return entry['data']

    def size(self) -> int:
        with self._lock:
            return len(self._store)

    def stats(self) -> dict:
        return dict(self._stats)

# Global cache instance
_cache = ThreatFeedCache(ttl_seconds=3600)

# In-memory loaded feeds
_phishtank_urls: set = set()
_openphish_urls: set = set()
_feed_last_updated: dict = {}


def load_openphish_feed(timeout: int = 10) -> int:
    """Load OpenPhish feed into memory."""
    global _openphish_urls
    if not HAS_REQUESTS:
        return 0
    try:
        r = req.get('https://openphish.com/feed.txt', timeout=timeout)
        urls = set(l.strip() for l in r.text.splitlines() if l.strip().startswith('http'))
        _openphish_urls = urls
        _feed_last_updated['openphish'] = datetime.utcnow()
        return len(urls)
    except Exception as e:
        return 0


def load_phishtank_feed(api_key: str = '', timeout: int = 15) -> int:
    """Load PhishTank verified feed."""
    global _phishtank_urls
    if not HAS_REQUESTS:
        return 0
    try:
        params = {'format': 'json'}
        if api_key:
            params['app_key'] = api_key
        r = req.get('https://data.phishtank.com/data/online-valid.json',
                    params=params, timeout=timeout)
        entries = r.json()
        urls = set(e.get('url', '') for e in entries if e.get('verified') == 'yes')
        _phishtank_urls = urls
        _feed_last_updated['phishtank'] = datetime.utcnow()
        return len(urls)
    except Exception:
        return 0


def check_threat_feeds(url: str) -> dict:
    """Check URL against loaded threat feeds."""
    # Normalize URL for matching
    url_clean = url.rstrip('/').lower()

    # Try cache first
    cached = _cache.get(url_clean)
    if cached:
        return cached

    result = {
        'in_openphish':         int(url_clean in _openphish_urls or
                                   any(url_clean in f for f in _openphish_urls)),
        'in_phishtank':         int(url_clean in _phishtank_urls or
                                   any(url_clean in f for f in _phishtank_urls)),
        'feed_match_count':     0,
        'threat_feed_risk':     0.0,
        'openphish_loaded':     int(len(_openphish_urls) > 0),
        'phishtank_loaded':     int(len(_phishtank_urls) > 0),
    }

    # Domain-level check
    try:
        domain = urlparse(url).netloc.lower()
        result['domain_in_openphish'] = int(
            any(domain in f for f in _openphish_urls)
        )
        result['domain_in_phishtank'] = int(
            any(domain in f for f in _phishtank_urls)
        )
    except Exception:
        result['domain_in_openphish'] = 0
        result['domain_in_phishtank'] = 0

    count = (result['in_openphish'] + result['in_phishtank'] +
             result['domain_in_openphish'] + result['domain_in_phishtank'])
    result['feed_match_count'] = min(count, 4)
    result['threat_feed_risk'] = round(min(count / 4.0, 1.0), 4)

    _cache.set(url_clean, result)
    return result

def get_feed_status() -> dict:
    return {
        'openphish_urls': len(_openphish_urls),
        'phishtank_urls': len(_phishtank_urls),
        'cache_size':     _cache.size(),
        'cache_stats':    _cache.stats(),
        'last_updated':   {k: v.isoformat() for k,v in _feed_last_updated.items()},
    }

def get_threat_feature_names() -> list:
    return [
        'in_openphish','in_phishtank','feed_match_count','threat_feed_risk',
        'openphish_loaded','phishtank_loaded','domain_in_openphish','domain_in_phishtank',
    ]
