"""
PhishGuard-X — ML Model Training for URL Intelligence Layer
Enhanced ensemble: GBC + RF + LR with 84-feature vector
"""

import os, json, joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_selection import RFE
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix
)
import random, string


def _random_string(n, chars=string.ascii_lowercase):
    return ''.join(random.choices(chars, k=n))

def _gen_legit_urls(n=2000):
    domains = [
        'google.com','amazon.com','microsoft.com','apple.com','facebook.com',
        'github.com','stackoverflow.com','reddit.com','bbc.com','nytimes.com',
        'netflix.com','spotify.com','linkedin.com','twitter.com','youtube.com',
        'wikipedia.org','dropbox.com','salesforce.com','adobe.com','ibm.com',
    ]
    paths = ['','/home','/about','/products','/docs','/help','/api/v1/users',
             '/search?q=python','/settings','/dashboard','/news','/contact']
    urls = []
    for _ in range(n):
        urls.append(f"https://{random.choice(domains)}{random.choice(paths)}")
    return urls

def _gen_phish_urls(n=2000):
    brands = ['paypal','amazon','apple','microsoft','google','facebook',
              'netflix','paytm','hdfc','stripe','discord','dhl']
    tlds   = ['tk','ml','ga','cf','xyz','top','online']
    attacks = [
        # IP-based
        lambda: f"http://{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}/login",
        # Brand in subdomain
        lambda: f"http://{random.choice(brands)}-secure.{_random_string(8)}.{random.choice(tlds)}/signin",
        # Brand in domain
        lambda: f"http://www.{random.choice(brands)}-verify.com/account/confirm",
        # Suspicious TLD
        lambda: f"http://{_random_string(10)}.{random.choice(tlds)}/login/verify?user=x",
        # Leet spoof
        lambda: f"http://www.{''.join(c if random.random()>0.3 else {'a':'4','e':'3','o':'0','i':'1'}.get(c,c) for c in random.choice(brands))}.com/verify",
        # Long URL with keywords
        lambda: f"http://{_random_string(12)}.com/secure/banking/{random.choice(brands)}-verify-{_random_string(8)}/",
        # URL shortener
        lambda: f"https://bit.ly/{_random_string(6, string.ascii_letters+string.digits)}",
        # Double encoded
        lambda: f"http://{_random_string(10)}.com/%2561%2564%256d%2569%256e/login?user={_random_string(8)}",
        # @ sign
        lambda: f"http://secure@{_random_string(12)}.{random.choice(tlds)}/steal",
        # Redirect
        lambda: f"http://{_random_string(10)}.xyz/redirect?url=http://{_random_string(8)}.com/phish",
    ]
    urls = []
    for _ in range(n):
        try:
            urls.append(random.choice(attacks)())
        except Exception:
            urls.append(f"http://{_random_string(15)}.tk/login/verify")
    return urls

def generate_training_data(n_legit=2000, n_phish=2000, seed=42):
    random.seed(seed); np.random.seed(seed)
    legit = _gen_legit_urls(n_legit)
    phish = _gen_phish_urls(n_phish)
    urls  = legit + phish
    labels= [0]*n_legit + [1]*n_phish
    df    = pd.DataFrame({'url':urls,'label':labels})
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)

def _smote_oversample(X, y, random_state=42):
    rng = np.random.RandomState(random_state)
    classes, counts = np.unique(y, return_counts=True)
    if counts.max() == counts.min():
        perm = rng.permutation(len(X))
        return X[perm], y[perm]
    maj = classes[np.argmax(counts)]
    mino= classes[np.argmin(counts)]
    X_maj, X_min = X[y==maj], X[y==mino]
    y_maj, y_min = y[y==maj], y[y==mino]
    n_add = len(X_maj) - len(X_min)
    idx   = rng.choice(len(X_min), n_add, replace=True)
    noise = rng.normal(0, 0.05, (n_add, X_min.shape[1]))
    X_syn = X_min[idx] + noise
    y_syn = np.full(n_add, mino)
    X_out = np.vstack([X_maj, X_min, X_syn])
    y_out = np.concatenate([y_maj, y_min, y_syn])
    perm  = rng.permutation(len(X_out))
    return X_out[perm], y_out[perm]

def train_url_model(n_legit=2000, n_phish=2000, n_features=45, save_dir='models'):
    """Full training pipeline for URL intelligence ML model."""
    from layers.url_intelligence.feature_engine import batch_extract, get_feature_names

    print("[Train] Generating dataset...")
    df     = generate_training_data(n_legit, n_phish)
    print(f"[Train] Extracting features for {len(df)} URLs...")
    X_raw  = batch_extract(df['url'].tolist())
    y      = df['label'].values
    fnames = get_feature_names()
    print(f"[Train] Feature shape: {X_raw.shape}")

    # Clean NaN/Inf
    X_raw  = np.nan_to_num(X_raw, nan=0.0, posinf=10.0, neginf=0.0)

    # Split
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_raw, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale
    scaler = RobustScaler()
    X_tr   = scaler.fit_transform(X_tr)
    X_te   = scaler.transform(X_te)

    # Oversample
    X_tr, y_tr = _smote_oversample(X_tr, y_tr)
    print(f"[Train] After oversample: {X_tr.shape}")

    # RFE
    print(f"[Train] RFE: selecting {n_features} features...")
    rf_sel = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rfe    = RFE(rf_sel, n_features_to_select=min(n_features, X_tr.shape[1]), step=3)
    rfe.fit(X_tr, y_tr)
    X_tr_sel = rfe.transform(X_tr)
    X_te_sel = rfe.transform(X_te)
    sel_names= [fnames[i] for i in range(len(fnames)) if i < len(rfe.support_) and rfe.support_[i]]
    print(f"[Train] Selected: {sel_names}")

    # Build ensemble
    gbc = GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.1,
        subsample=0.8, random_state=42
    )
    rf  = RandomForestClassifier(
        n_estimators=200, max_depth=10, min_samples_split=5,
        random_state=42, n_jobs=-1
    )
    lr  = LogisticRegression(C=1.0, max_iter=2000, solver='saga', random_state=42)

    ensemble = VotingClassifier(
        estimators=[('gbc',gbc),('rf',rf),('lr',lr)],
        voting='soft', weights=[3,2,1], n_jobs=-1
    )
    print("[Train] Training ensemble...")
    ensemble.fit(X_tr_sel, y_tr)

    # Evaluate
    y_pred = ensemble.predict(X_te_sel)
    y_prob = ensemble.predict_proba(X_te_sel)[:,1]
    metrics = {
        'accuracy':  round(accuracy_score(y_te, y_pred), 4),
        'precision': round(precision_score(y_te, y_pred), 4),
        'recall':    round(recall_score(y_te, y_pred), 4),
        'f1_score':  round(f1_score(y_te, y_pred), 4),
        'roc_auc':   round(roc_auc_score(y_te, y_prob), 4),
        'confusion_matrix': confusion_matrix(y_te, y_pred).tolist(),
        'selected_features': sel_names,
        'n_features_total':  len(fnames),
        'n_features_selected': len(sel_names),
    }
    print("[Train] Metrics:")
    for k in ['accuracy','precision','recall','f1_score','roc_auc']:
        print(f"  {k}: {metrics[k]}")

    # Feature importances from RF
    rf_fitted = ensemble.named_estimators_['rf']
    importances = dict(sorted(
        zip(sel_names, rf_fitted.feature_importances_),
        key=lambda x: x[1], reverse=True
    ))
    metrics['feature_importances'] = {k: round(float(v),4) for k,v in importances.items()}

    # Save artifacts
    os.makedirs(save_dir, exist_ok=True)
    joblib.dump({'model':ensemble,'scaler':scaler,'rfe':rfe,
                 'feature_names':fnames,'selected_features':sel_names,
                 'metrics':metrics}, f'{save_dir}/url_model.pkl')
    with open(f'{save_dir}/url_metrics.json','w') as f:
        json.dump(metrics, f, indent=2)
    print(f"[Train] Saved to {save_dir}/url_model.pkl")
    return metrics

def load_url_model(save_dir='models'):
    path = f'{save_dir}/url_model.pkl'
    if not os.path.exists(path):
        return None
    return joblib.load(path)
