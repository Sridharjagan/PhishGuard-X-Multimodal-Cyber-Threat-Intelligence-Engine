"""
PhishGuard-X — Layer 8: Explainable AI
SHAP-based feature importance + evidence report generation
"""

import json, time
import numpy as np

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False

# Severity thresholds for human-readable explanations
FEATURE_DESCRIPTIONS = {
    'has_ip':                    ('IP address used instead of domain name',               'critical'),
    'has_at_sign':               ('@ symbol in URL — credential pre-fill attack',          'critical'),
    'brand_name_in_subdomain':   ('Brand name spoofed in subdomain',                       'critical'),
    'brand_name_in_domain':      ('Brand name in registered domain (not official domain)', 'critical'),
    'has_homograph_spoof':       ('Unicode homograph attack detected',                     'critical'),
    'has_leet_brand_spoof':      ('Leetspeak brand spoofing (e.g. faceb00k→facebook)',     'critical'),
    'is_mixed_script':           ('Mixed Unicode scripts — likely IDN homograph attack',   'critical'),
    'double_encoded':            ('Double URL encoding — obfuscation technique',           'high'),
    'has_url_shortener':         ('URL shortener masking true destination',                'high'),
    'is_suspicious_tld':         ('Suspicious top-level domain (.tk/.xyz/.ml)',            'high'),
    'has_homograph_spoof':       ('Homograph Unicode attack detected',                     'high'),
    'external_form_target':      ('Form submits data to external domain',                  'critical'),
    'has_password_input':        ('Password input field detected on suspicious page',      'high'),
    'js_eval_count':             ('Suspicious eval() JavaScript obfuscation detected',     'high'),
    'domain_very_new':           ('Domain registered within last 7 days',                  'high'),
    'domain_age_risk':           ('Very new domain — high phishing risk',                  'high'),
    'fast_flux_risk':            ('Very low DNS TTL — fast-flux hosting detected',         'high'),
    'in_openphish':              ('URL confirmed in OpenPhish threat feed',                'critical'),
    'in_phishtank':              ('URL confirmed in PhishTank verified phishing feed',     'critical'),
    'title_brand_mismatch':      ('Page title mentions brand not matching domain',         'medium'),
    'favicon_mismatch':          ('Favicon loaded from different domain',                  'medium'),
    'suspicious_keyword_count':  ('Multiple phishing keywords in URL',                    'medium'),
    'has_redirect_param':        ('Redirect parameter in URL',                            'medium'),
    'has_security_keyword':      ('Security/verification keywords detected',              'low'),
    'has_login_keyword':         ('Login/signin keywords detected',                       'low'),
    'url_length':                ('Unusually long URL',                                   'low'),
    'domain_entropy':            ('High domain randomness (Shannon entropy)',              'low'),
}

class PhishGuardExplainer:
    def __init__(self, model=None, feature_names: list = None):
        self.model         = model
        self.feature_names = feature_names or []
        self._explainer    = None
        self._background   = None

    def fit_shap(self, X_background: np.ndarray):
        """Fit SHAP TreeExplainer on background data."""
        if not HAS_SHAP or self.model is None:
            return
        try:
            self._explainer  = shap.TreeExplainer(self.model)
            self._background = X_background
        except Exception as e:
            print(f"[Explainer] SHAP fit failed: {e}")

    def explain(self, X: np.ndarray, feature_dict: dict = None) -> dict:
        """Generate full explanation for a single feature vector."""
        explanation = {
            'shap_values':        {},
            'top_features':       [],
            'risk_indicators':    [],
            'counterfactual':     [],
            'analyst_summary':    '',
            'explanation_method': 'rule-based',
        }

        # ── SHAP explanations ──────────────────────────────────
        if HAS_SHAP and self._explainer is not None:
            try:
                sv = self._explainer.shap_values(X)
                if isinstance(sv, list):
                    sv = sv[1]   # class 1 (phishing) SHAP values
                sv_flat = sv.flatten()
                explanation['shap_values'] = {
                    name: round(float(sv_flat[i]), 4)
                    for i, name in enumerate(self.feature_names)
                    if i < len(sv_flat)
                }
                # Top 5 by absolute SHAP
                top = sorted(explanation['shap_values'].items(),
                             key=lambda x: abs(x[1]), reverse=True)[:5]
                explanation['top_features'] = [
                    {'feature': k, 'shap_value': v,
                     'direction': 'phishing' if v > 0 else 'legitimate'}
                    for k, v in top
                ]
                explanation['explanation_method'] = 'shap'
            except Exception as e:
                pass

        # ── Rule-based risk indicators (always computed) ──────
        fd = feature_dict or {}
        indicators = []
        for feat, (desc, sev) in FEATURE_DESCRIPTIONS.items():
            val = fd.get(feat, 0)
            if isinstance(val, float) and val > 0.5:
                triggers = True
            elif isinstance(val, int) and val == 1:
                triggers = True
            elif feat == 'suspicious_keyword_count' and val >= 2:
                triggers = True
            elif feat == 'url_length' and val > 100:
                triggers = True
            elif feat == 'domain_entropy' and val > 4.0:
                triggers = True
            elif feat == 'js_eval_count' and val >= 1:
                triggers = True
            else:
                triggers = False

            if triggers:
                indicators.append({'name': desc, 'severity': sev,
                                   'feature': feat, 'value': val})

        # Sort by severity
        sev_order = {'critical':0,'high':1,'medium':2,'low':3}
        indicators.sort(key=lambda x: sev_order.get(x['severity'], 4))
        explanation['risk_indicators'] = indicators[:10]

        # ── Counterfactual hints ──────────────────────────────
        cf = []
        if fd.get('has_https', 1) == 0:
            cf.append('Adding HTTPS would reduce threat confidence')
        if fd.get('count_hyphens', 0) >= 2:
            cf.append('Removing hyphens from domain would reduce risk')
        if fd.get('is_suspicious_tld', 0):
            cf.append('Moving to a .com/.org TLD would reduce risk')
        if fd.get('suspicious_keyword_count', 0) >= 2:
            cf.append('Removing security/login keywords from URL path would reduce risk')
        if fd.get('brand_name_in_subdomain', 0):
            cf.append('Brand name in subdomain is primary phishing signal')
        explanation['counterfactual'] = cf[:3]

        # ── Analyst summary ───────────────────────────────────
        critical = [i for i in indicators if i['severity'] == 'critical']
        high     = [i for i in indicators if i['severity'] == 'high']
        n_ind    = len(indicators)

        if n_ind == 0:
            explanation['analyst_summary'] = (
                'No phishing indicators detected. URL structure, domain, '
                'and content appear consistent with legitimate usage.'
            )
        elif critical:
            top_crit = critical[0]['name']
            explanation['analyst_summary'] = (
                f'HIGH CONFIDENCE PHISHING: {n_ind} risk indicators detected. '
                f'Critical signal: {top_crit}. '
                f'Immediate action recommended — do not interact with this URL.'
            )
        elif high:
            top_high = high[0]['name']
            explanation['analyst_summary'] = (
                f'SUSPICIOUS URL: {n_ind} risk indicators detected. '
                f'Primary signal: {top_high}. '
                f'Exercise caution — verify URL authenticity before proceeding.'
            )
        else:
            explanation['analyst_summary'] = (
                f'LOW-MODERATE RISK: {n_ind} minor indicators detected. '
                f'URL shows some suspicious characteristics but no critical signals. '
                f'Context-dependent — review indicators before proceeding.'
            )

        return explanation


# Global explainer instance
_explainer = PhishGuardExplainer()

def get_explainer() -> PhishGuardExplainer:
    return _explainer
