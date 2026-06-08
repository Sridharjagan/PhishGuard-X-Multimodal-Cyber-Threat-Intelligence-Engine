# PhishGuard-X v2.0 — Multi-Modal Phishing Threat Intelligence

## Architecture: 9 Intelligence Layers

| Layer | Module | Status |
|---|---|---|
| 1. URL Intelligence | `layers/url_intelligence/` | ✅ 84 features, homograph, leet, obfuscation |
| 2. Domain Intelligence | `layers/domain_intelligence/` | ✅ WHOIS+DNS+SSL+Registrar |
| 3. Content Intelligence | `layers/content_intelligence/` | ✅ HTML+JS+Forms+Social Eng |
| 4. Vision Intelligence | `layers/vision_intelligence/` | 🔧 Requires playwright+easyocr |
| 5. LLM Reasoning | `layers/llm_reasoning/` | 🔧 Requires llama-cpp-python |
| 6. Threat Intelligence | `layers/threat_intelligence/` | ✅ OpenPhish+PhishTank feeds |
| 7. Attack Graph | `layers/attack_graph/` | ✅ NetworkX graph + cluster detection |
| 8. Explainability | `layers/explainability/` | ✅ SHAP + counterfactuals + analyst reports |
| 9. Ensemble Fusion | `layers/ensemble_fusion/` | ✅ Adaptive Bayesian fusion |

## Quick Start

```bash
pip install scikit-learn pandas numpy flask joblib scipy requests dnspython python-whois beautifulsoup4 networkx
python train.py          # Train URL ensemble model (84 features)
python app.py            # Launch at http://localhost:5000
```

## API

```bash
# Single URL (URL + XAI layers)
curl -X POST http://localhost:5000/api/v2/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://paytm-secure-login.example.com","layers":["url","xai"]}'

# Full multi-modal (URL + Domain + Content + Threat + Graph + XAI)
curl -X POST http://localhost:5000/api/v2/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://suspicious.tk/login","layers":["url","domain","content","threat","graph","xai"]}'

# Batch (up to 50 URLs)
curl -X POST http://localhost:5000/api/v2/batch \
  -H "Content-Type: application/json" \
  -d '{"urls":["https://google.com","http://evil.tk/login"]}'
```

## New Features vs PhishGuard v4

| Feature | v4 | X v2.0 |
|---|---|---|
| URL features | 56 | 84 |
| Homograph/Unicode detection | ❌ | ✅ |
| WHOIS/DNS/SSL analysis | ❌ | ✅ |
| HTML/JS content analysis | ❌ | ✅ |
| Social engineering detection | ❌ | ✅ |
| OpenPhish/PhishTank feeds | ❌ | ✅ |
| Attack graph intelligence | ❌ | ✅ |
| SHAP explainability | ❌ | ✅ |
| Analyst explanations | ❌ | ✅ |
| Counterfactual hints | ❌ | ✅ |
| Adaptive Bayesian fusion | ❌ | ✅ |
| Layer score breakdown UI | ❌ | ✅ |
