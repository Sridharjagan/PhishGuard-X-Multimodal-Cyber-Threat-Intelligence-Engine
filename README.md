# PhishGuard-X-Multimodal-Cyber-Threat-Intelligence-Engine
AI-powered multimodal phishing threat intelligence platform combining machine learning, LLMs, computer vision, graph analytics, and threat intelligence for real-time phishing detection and attribution.

# 🛡️ PhishGuard-X

### Multimodal AI-Powered Phishing Threat Intelligence Platform

PhishGuard-X is a next-generation cybersecurity platform designed to detect, analyze, explain, and attribute phishing attacks using a combination of Artificial Intelligence, Threat Intelligence, Machine Learning, Large Language Models (LLMs), Computer Vision, and Graph Intelligence.

Unlike traditional phishing detectors that rely solely on URL analysis, PhishGuard-X performs multi-layer security analysis across URLs, domains, website content, visual elements, infrastructure relationships, and threat intelligence feeds.

---

## 🚀 Vision

PhishGuard-X aims to evolve phishing detection from simple classification into a complete cyber threat intelligence system capable of:

- Detecting phishing attacks
- Explaining why a site is malicious
- Identifying targeted brands
- Discovering phishing infrastructure
- Detecting social engineering tactics
- Supporting security analysts with explainable AI

---

# 🏗 System Architecture

```text
                     ┌─────────────────────┐
                     │    User Request     │
                     └──────────┬──────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ URL Intelligence Engine      │
                └──────────────────────────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ Domain Intelligence Engine   │
                └──────────────────────────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ Content Intelligence Engine  │
                └──────────────────────────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ Vision Intelligence Engine   │
                └──────────────────────────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ LLM Security Reasoner        │
                └──────────────────────────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ Threat Intelligence Layer    │
                └──────────────────────────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ Graph Intelligence Engine    │
                └──────────────────────────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ Explainable AI Layer         │
                └──────────────────────────────┘
                                │
                                ▼

                ┌──────────────────────────────┐
                │ Threat Verdict & Attribution │
                └──────────────────────────────┘
```

---

# 🔍 Core Features

## URL Intelligence

- Lexical URL Analysis
- Entropy-Based Detection
- Homograph Detection
- Unicode Attack Detection
- Leetspeak Brand Detection
- Suspicious TLD Detection
- Redirect Analysis
- URL Reputation Scoring

---

## Domain Intelligence

- WHOIS Analysis
- Domain Age Verification
- Registrar Reputation
- DNS Analysis
- MX Record Validation
- SPF Validation
- DMARC Validation
- SSL Certificate Inspection

---

## Website Content Intelligence

- HTML Parsing
- Credential Harvesting Detection
- Login Form Detection
- Hidden Input Detection
- Obfuscated JavaScript Detection
- Suspicious Script Detection

---

## Vision Intelligence

- Screenshot Analysis
- OCR Extraction
- Brand Logo Recognition
- Visual Similarity Scoring
- Fake Login Page Detection

---

## LLM Security Reasoning

- Social Engineering Detection
- Fear Tactic Analysis
- Urgency Detection
- Psychological Manipulation Detection
- Human-Readable Threat Explanation

---

## Threat Intelligence

- OpenPhish Integration
- PhishTank Integration
- IOC Enrichment
- Reputation Scoring
- Threat Feed Correlation

---

## Graph Intelligence

- Infrastructure Mapping
- URL Relationships
- Domain Relationships
- Redirect Chains
- Brand Target Analysis
- Phishing Campaign Discovery

---

## Explainable AI

- SHAP Analysis
- Feature Attribution
- Threat Attribution
- Analyst Reports
- Explainable Decisions

---

# 🧠 AI Models

| Component | Model |
|------------|--------|
| URL Detection | XGBoost |
| Domain Analysis | LightGBM |
| Content Analysis | Random Forest |
| Vision Analysis | CLIP |
| OCR | EasyOCR |
| LLM Reasoning | TinyLlama |
| Graph Analysis | GraphSAGE |
| Explainability | SHAP |

---

# 📂 Project Structure

```text
PhishGuard-X/
│
├── data/
│
├── datasets/
│
├── models/
│
├── notebooks/
│
├── src/
│   ├── url_intelligence/
│   ├── domain_intelligence/
│   ├── content_intelligence/
│   ├── vision_intelligence/
│   ├── llm_reasoning/
│   ├── graph_intelligence/
│   ├── explainability/
│   ├── threat_intelligence/
│   └── api/
│
├── frontend/
│
├── browser_extension/
│
├── docs/
│
├── tests/
│
├── research/
│
├── deployment/
│
├── train.py
│
├── app.py
│
├── requirements.txt
│
└── README.md
```

---

# 📊 Supported Datasets

- PhishTank
- OpenPhish
- Alexa Top Domains
- Tranco Dataset
- Common Crawl
- CIC Phishing Dataset
- UCI URL Dataset

---

# ⚙️ Installation

```bash
git clone https://github.com/yourusername/PhishGuard-X.git

cd PhishGuard-X

pip install -r requirements.txt
```

---

# 🚀 Run

```bash
python train.py
```

```bash
python app.py
```

Open:

```text
http://localhost:5000
```

---

# 📈 Research Objectives

- Real-Time Phishing Detection
- Multimodal Threat Intelligence
- Explainable AI for Cybersecurity
- Graph-Based Attack Attribution
- LLM-Based Social Engineering Detection
- Adversarially Robust Detection Models

---

# 🎯 Future Roadmap

## Phase 1

- URL Intelligence Engine
- Domain Intelligence Engine

## Phase 2

- Content Intelligence
- Vision Intelligence

## Phase 3

- LLM Threat Reasoning

## Phase 4

- Graph Neural Network Analysis

## Phase 5

- Browser Extension

## Phase 6

- Cloud Deployment

---

# 📚 Research Contributions

- Multimodal phishing detection
- Cross-layer threat correlation
- AI-powered threat attribution
- Graph-based phishing campaign discovery
- Explainable phishing intelligence
- Adversarial phishing robustness

---

# 🏆 Applications

- SOC Operations
- Threat Intelligence Teams
- Security Analysts
- Enterprise Email Security
- Browser Security Extensions
- Managed Security Service Providers (MSSPs)

---

# 📜 License

MIT License

---

# 👨‍💻 Author

Sridhar J

B.Tech Artificial Intelligence & Data Science

Cybersecurity Researcher | AI Engineer | Threat Intelligence Enthusiast

---

## ⭐ If you find this project useful, consider giving it a star.
