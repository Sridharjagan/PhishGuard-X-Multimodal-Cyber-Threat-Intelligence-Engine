"""
PhishGuard-X — Main Flask Application
Multi-modal phishing threat intelligence platform
Layers: URL + Domain + Content + Threat Intelligence + Graph + XAI + Fusion
"""

import os, sys, json, time, joblib, threading
import numpy as np
from flask import Flask, request, jsonify, render_template

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from layers.url_intelligence.feature_engine   import (
    extract_url_features, extract_feature_vector, get_feature_names
)
from layers.domain_intelligence.domain_analyzer import analyze_domain
from layers.content_intelligence.content_analyzer import analyze_content
from layers.threat_intelligence.threat_feed      import (
    check_threat_feeds, get_feed_status, load_openphish_feed
)
from layers.attack_graph.graph_intelligence      import get_graph, get_graph_feature_names
from layers.explainability.explainer             import get_explainer
from layers.ensemble_fusion.fusion_engine        import fuse

app = Flask(__name__, template_folder='templates', static_folder='static')

@app.after_request
def cors(r):
    r.headers['Access-Control-Allow-Origin']  = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return r

# ── Global model state ──────────────────────────────────────────
_url_model  = None
_model_meta = {}
_graph      = get_graph()
_explainer  = get_explainer()

def load_models():
    global _url_model, _model_meta
    try:
        from layers.ensemble_fusion.ml_model import load_url_model
        data = load_url_model('models')
        if data:
            _url_model = data
            _model_meta = data.get('metrics', {})
            feat_names  = data.get('feature_names', [])
            _explainer.model         = data['model']
            _explainer.feature_names = feat_names
            print(f"[App] ML model loaded — {len(feat_names)} features")
    except Exception as e:
        print(f"[App] Model load failed: {e} — heuristic mode")

# ── Analysis pipeline ───────────────────────────────────────────

def _url_ml_score(feature_vector: np.ndarray) -> float:
    """Get ML probability from URL model."""
    if _url_model is None:
        return -1.0
    try:
        scaler = _url_model['scaler']
        rfe    = _url_model['rfe']
        model  = _url_model['model']
        X_scaled = scaler.transform(feature_vector.reshape(1,-1))
        X_sel    = rfe.transform(X_scaled)
        prob = model.predict_proba(X_sel)[0][1]
        return float(prob)
    except Exception as e:
        return -1.0


def _heuristic_score(features: dict) -> float:
    """Rule-based heuristic confidence score."""
    RULES = [
        ('has_ip',                  lambda v: v==1, 3.5),
        ('has_at_sign',             lambda v: v==1, 3.0),
        ('brand_name_in_subdomain', lambda v: v==1, 3.5),
        ('brand_name_in_domain',    lambda v: v==1, 3.0),
        ('has_homograph_spoof',     lambda v: v==1, 4.0),
        ('has_leet_brand_spoof',    lambda v: v==1, 3.5),
        ('is_mixed_script',         lambda v: v==1, 3.0),
        ('double_encoded',          lambda v: v==1, 2.5),
        ('has_url_shortener',       lambda v: v==1, 2.5),
        ('is_suspicious_tld',       lambda v: v==1, 1.8),
        ('suspicious_keyword_count',lambda v: v>=3, 2.0),
        ('suspicious_keyword_count',lambda v: v>=1, 1.2),
        ('has_redirect_param',      lambda v: v==1, 1.5),
        ('count_hyphens',           lambda v: v>=2, 1.4),
        ('brand_name_in_path',      lambda v: v==1, 1.0),
        ('has_port',                lambda v: v==1, 0.9),
        ('has_https',               lambda v: v==0, 0.9),
        ('has_number_substitution', lambda v: v==1, 0.9),
        ('domain_entropy',          lambda v:v>4.0, 0.8),
        ('url_length',              lambda v:v>100, 0.8),
        ('has_financial_keyword',   lambda v: v==1, 0.7),
        ('has_security_keyword',    lambda v: v==1, 0.6),
        ('has_encoded_chars',       lambda v: v==1, 0.6),
        ('path_depth',              lambda v: v>=5, 0.5),
        ('has_login_keyword',       lambda v: v==1, 0.5),
    ]
    score = 0.0
    seen  = set()
    for feat, cond, w in RULES:
        val = features.get(feat, 0)
        if cond(val) and feat not in seen:
            score += w
            seen.add(feat)
    return float(min(score / 9.0, 1.0) ** 0.65)


def analyze_url_full(url: str, layers: list = None, timeout: int = 8) -> dict:
    """
    Full multi-modal analysis pipeline.
    layers: list of layer names to run. None = run all fast layers.
    """
    t_start = time.time()
    if not url.startswith(('http://','https://')):
        url = 'http://' + url

    enabled = set(layers) if layers else {'url','domain','threat','graph','xai'}
    # 'content' is opt-in — network-heavy
    # 'domain'  is opt-in — DNS/WHOIS latency

    result = {
        'url':          url,
        'layers_run':   [],
        'layer_scores': {},
        'all_features': {},
    }

    # ── Layer 1: URL Intelligence (always run) ──────────────────
    url_feats = extract_url_features(url)
    url_vec   = np.array([url_feats.get(k,0) for k in get_feature_names()], dtype=np.float64)
    url_vec   = np.nan_to_num(url_vec, nan=0.0, posinf=10.0, neginf=0.0)
    result['all_features'].update(url_feats)
    result['layers_run'].append('url')

    # ML score
    ml_prob = _url_ml_score(url_vec)
    heur    = _heuristic_score(url_feats)
    if ml_prob >= 0:
        url_score = max(ml_prob, heur * 0.65)
        url_mode  = 'ml+heuristic'
    else:
        url_score = heur
        url_mode  = 'heuristic'
    result['layer_scores']['url'] = url_score
    result['url_analysis'] = {
        'ml_probability':    round(ml_prob, 4) if ml_prob >= 0 else None,
        'heuristic_score':   round(heur, 4),
        'final_score':       round(url_score, 4),
        'mode':              url_mode,
        'homograph_detected':bool(url_feats.get('has_homograph_spoof')),
        'leet_spoof':        bool(url_feats.get('has_leet_brand_spoof')),
        'mixed_script':      bool(url_feats.get('is_mixed_script')),
    }

    is_trusted = bool(url_feats.get('is_trusted_official'))

    # ── Layer 2: Domain Intelligence ───────────────────────────
    if 'domain' in enabled and not is_trusted:
        try:
            dom_feats = analyze_domain(url, timeout=timeout)
            result['all_features'].update(dom_feats)
            result['layers_run'].append('domain')
            # Normalize domain risk to [0,1]
            dom_score = min(dom_feats.get('domain_risk_score',0) / 10.0, 1.0)
            result['layer_scores']['domain'] = dom_score
            result['domain_analysis'] = {
                'age_days':         dom_feats.get('domain_age_days', -1),
                'age_risk':         dom_feats.get('domain_age_risk', 0),
                'very_new':         bool(dom_feats.get('domain_very_new')),
                'high_risk_reg':    bool(dom_feats.get('high_risk_registrar')),
                'has_spf':          bool(dom_feats.get('has_spf')),
                'has_dmarc':        bool(dom_feats.get('has_dmarc')),
                'fast_flux':        bool(dom_feats.get('fast_flux_risk')),
                'ssl_issuer_risk':  bool(dom_feats.get('ssl_issuer_risk')),
                'domain_score':     round(dom_score, 4),
            }
        except Exception as e:
            result['domain_analysis'] = {'error': str(e)}
    else:
        result['layer_scores']['domain'] = url_score * 0.5

    # ── Layer 3: Content Intelligence (opt-in) ──────────────────
    if 'content' in enabled and not is_trusted:
        try:
            cont_feats = analyze_content(url)
            result['all_features'].update(cont_feats)
            result['layers_run'].append('content')
            cont_score = min(cont_feats.get('content_risk_score',0) / 10.0, 1.0)
            result['layer_scores']['content'] = cont_score
            result['content_analysis'] = {
                'fetch_success':   bool(cont_feats.get('content_fetch_success')),
                'password_input':  bool(cont_feats.get('has_password_input')),
                'external_form':   bool(cont_feats.get('external_form_target')),
                'js_obfuscation':  cont_feats.get('js_obfuscation_score', 0),
                'se_total':        cont_feats.get('se_total_score', 0),
                'title_mismatch':  bool(cont_feats.get('title_brand_mismatch')),
                'content_score':   round(cont_score, 4),
            }
        except Exception as e:
            result['content_analysis'] = {'error': str(e)}
    else:
        result['layer_scores']['content'] = url_score * 0.6

    # ── Layer 6: Threat Intelligence ───────────────────────────
    if 'threat' in enabled:
        threat_feats = check_threat_feeds(url)
        result['all_features'].update(threat_feats)
        result['layers_run'].append('threat')
        threat_score = threat_feats.get('threat_feed_risk', 0.0)
        result['layer_scores']['threat'] = threat_score
        result['threat_analysis'] = {
            'in_openphish':  bool(threat_feats.get('in_openphish')),
            'in_phishtank':  bool(threat_feats.get('in_phishtank')),
            'feed_matches':  threat_feats.get('feed_match_count', 0),
            'threat_score':  round(threat_score, 4),
        }

    # ── Layer 7: Attack Graph ───────────────────────────────────
    if 'graph' in enabled:
        graph_feats = _graph.get_url_graph_features(url)
        # Add URL to graph with URL features
        _graph.add_url(url, url_feats, label=-1)
        result['all_features'].update(graph_feats)
        result['layers_run'].append('graph')
        known = graph_feats.get('graph_known_node', 0)
        cluster_size = graph_feats.get('graph_cluster_size', 0)
        neighbor_risk = graph_feats.get('graph_neighbor_risk_avg', 0.0)
        graph_score = float(np.clip(
            (known * 0.3) + (min(cluster_size,10)/10 * 0.4) + (neighbor_risk/10 * 0.3),
            0.0, 1.0
        ))
        result['layer_scores']['graph'] = graph_score
        result['graph_analysis'] = {
            'known_node':      bool(known),
            'cluster_size':    cluster_size,
            'neighbor_risk':   round(neighbor_risk, 3),
            'graph_score':     round(graph_score, 4),
        }

    # ── Layer 9: Ensemble Fusion ────────────────────────────────
    fusion = fuse(result['layer_scores'], result['all_features'], is_trusted)
    result.update({
        'prediction':   fusion['prediction'],
        'confidence':   fusion['confidence'],
        'risk_score':   fusion['risk_score'],
        'risk_level':   fusion['risk_level'],
        'layer_contributions': fusion['layer_contributions'],
    })

    # ── Layer 8: Explainability ─────────────────────────────────
    if 'xai' in enabled:
        xai = _explainer.explain(url_vec.reshape(1,-1), result['all_features'])
        result['explanation'] = {
            'top_features':    xai['top_features'],
            'risk_indicators': xai['risk_indicators'],
            'counterfactual':  xai['counterfactual'],
            'analyst_summary': xai['analyst_summary'],
            'method':          xai['explanation_method'],
        }
        result['layers_run'].append('xai')

    result['analysis_time_ms'] = round((time.time()-t_start)*1000, 2)
    result['model_version']    = '2.0.0'

    return result


# ── Routes ─────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/v2/analyze', methods=['POST','OPTIONS'])
def api_analyze():
    if request.method == 'OPTIONS': return '', 204
    data = request.get_json()
    if not data or not data.get('url','').strip():
        return jsonify({'error':'url is required'}), 400
    layers  = data.get('layers', None)
    timeout = int(data.get('timeout', 8))
    try:
        result = analyze_url_full(data['url'].strip(), layers=layers, timeout=timeout)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/v2/batch', methods=['POST','OPTIONS'])
def api_batch():
    if request.method == 'OPTIONS': return '', 204
    data = request.get_json()
    if not data or 'urls' not in data:
        return jsonify({'error':'urls list required'}), 400
    urls    = data['urls'][:50]
    layers  = data.get('layers', None)
    results = []
    for url in urls:
        try:
            results.append(analyze_url_full(url.strip(), layers=layers, timeout=5))
        except Exception as e:
            results.append({'url':url,'error':str(e)})
    return jsonify({'results':results,'total':len(results)})

@app.route('/api/v2/metrics')
def api_metrics():
    return jsonify({
        'model_metrics': _model_meta,
        'graph_stats':   _graph.stats(),
        'feed_status':   get_feed_status(),
        'feature_count': len(get_feature_names()),
    })

@app.route('/api/v2/status')
def api_status():
    return jsonify({
        'status':        'running',
        'version':       '2.0.0',
        'model_loaded':  _url_model is not None,
        'layers':        ['url','domain','content','threat','graph','xai','fusion'],
        'features':      len(get_feature_names()),
        'graph_nodes':   _graph.stats().get('nodes',0),
        'feed_status':   get_feed_status(),
    })

@app.route('/api/v2/graph/stats')
def api_graph():
    return jsonify(_graph.stats())

# ── Boot ───────────────────────────────────────────────────────
load_models()

if __name__ == '__main__':
    print("\n[PhishGuard-X] Starting at http://localhost:5000")
    print("[PhishGuard-X] API: POST /api/v2/analyze  {url, layers?}")
    print("[PhishGuard-X] Layers: url | domain | content | threat | graph | xai\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
