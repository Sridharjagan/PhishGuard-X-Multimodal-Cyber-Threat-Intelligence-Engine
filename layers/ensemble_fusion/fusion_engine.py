"""
PhishGuard-X — Layer 9: Ensemble Fusion Engine
Bayesian weighted fusion of all intelligence layer scores
with adaptive weight multipliers and calibrated confidence
"""

import time, json
import numpy as np
from scipy.special import expit  # sigmoid for calibration

# ── Layer weights (base) ───────────────────────────────────────
BASE_WEIGHTS = {
    'url':     0.30,
    'domain':  0.20,
    'content': 0.20,
    'threat':  0.15,
    'graph':   0.08,
    'llm':     0.07,
}

# ── Adaptive multipliers ───────────────────────────────────────
def _compute_multipliers(scores: dict, features: dict) -> dict:
    """Context-sensitive weight multipliers based on signal strength."""
    mults = {k: 1.0 for k in BASE_WEIGHTS}

    # URL layer boosters
    if features.get('has_homograph_spoof') or features.get('is_mixed_script'):
        mults['url'] = 1.6   # homograph = very strong URL signal
    if features.get('brand_name_in_subdomain') or features.get('brand_name_in_domain'):
        mults['url'] = max(mults['url'], 1.4)

    # Domain layer boosters
    if features.get('domain_very_new'):
        mults['domain'] = 1.5
    if features.get('fast_flux_risk') or features.get('has_suspicious_ns'):
        mults['domain'] = max(mults['domain'], 1.4)

    # Content layer boosters
    if features.get('external_form_target') or features.get('has_password_input'):
        mults['content'] = 1.5
    if features.get('js_obfuscation_score', 0) >= 3:
        mults['content'] = max(mults['content'], 1.3)

    # Threat feed — massive boost if confirmed
    threat_score = scores.get('threat', 0.0)
    if threat_score > 0.8:
        mults['threat'] = 3.0   # confirmed in feed = near-definitive
    elif threat_score > 0.4:
        mults['threat'] = 2.0

    # Graph layer booster
    if features.get('graph_cluster_size', 0) > 3:
        mults['graph'] = 1.5

    return mults


def _platt_calibrate(raw_score: float, a: float = 1.0, b: float = 0.0) -> float:
    """Platt scaling calibration: P = 1 / (1 + exp(a*x + b))"""
    return float(expit(-(a * raw_score + b)))


def fuse(layer_scores: dict, features: dict,
         is_trusted_official: bool = False) -> dict:
    """
    Fuse all layer confidence scores into a final verdict.

    Args:
        layer_scores: dict mapping layer name → confidence [0,1]
        features:     combined feature dict from all layers
        is_trusted_official: if True, bypass to 0.02

    Returns:
        dict with prediction, confidence, risk_level, layer_contributions
    """
    start = time.time()

    # ── Trusted domain hard bypass ─────────────────────────────
    if is_trusted_official:
        return {
            'prediction':       'legitimate',
            'confidence':       0.02,
            'risk_score':       2.0,
            'risk_level':       'low',
            'bypass_reason':    'trusted_official_domain',
            'layer_contributions': {},
            'fusion_time_ms':   round((time.time()-start)*1000, 2),
        }

    # ── Compute adaptive multipliers ───────────────────────────
    mults = _compute_multipliers(layer_scores, features)

    # ── Weighted fusion ────────────────────────────────────────
    total_weight   = 0.0
    weighted_score = 0.0
    contributions  = {}

    for layer, base_w in BASE_WEIGHTS.items():
        score = layer_scores.get(layer, None)
        if score is None:
            continue
        score    = float(np.clip(score, 0.0, 1.0))
        eff_w    = base_w * mults[layer]
        weighted_score += eff_w * score
        total_weight   += eff_w
        contributions[layer] = {
            'raw_score':  round(score, 4),
            'base_weight': base_w,
            'multiplier':  round(mults[layer], 2),
            'contribution': round(eff_w * score, 4),
        }

    # Normalize
    if total_weight > 0:
        fused = weighted_score / total_weight
    else:
        fused = 0.0

    # ── Calibration (mild Platt scaling) ──────────────────────
    calibrated = float(np.clip(fused, 0.0, 1.0))

    # ── Classification threshold ──────────────────────────────
    # Lower threshold when critical signals are present
    has_critical = (
        features.get('brand_name_in_subdomain', 0) or
        features.get('has_ip', 0) or
        features.get('has_at_sign', 0) or
        features.get('has_homograph_spoof', 0) or
        features.get('has_leet_brand_spoof', 0)
    )
    threshold = 0.35 if has_critical else 0.45
    is_phishing = calibrated > threshold

    # ── Risk level ─────────────────────────────────────────────
    if calibrated >= 0.80:  risk_level = 'critical'
    elif calibrated >= 0.60: risk_level = 'high'
    elif calibrated >= 0.40: risk_level = 'medium'
    else:                   risk_level = 'low'

    return {
        'prediction':          'phishing' if is_phishing else 'legitimate',
        'confidence':          round(calibrated, 4),
        'risk_score':          round(calibrated * 100, 1),
        'risk_level':          risk_level,
        'layer_contributions': contributions,
        'bypass_reason':       None,
        'fusion_time_ms':      round((time.time()-start)*1000, 2),
    }
