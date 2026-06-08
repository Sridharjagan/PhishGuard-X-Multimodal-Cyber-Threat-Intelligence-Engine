"""PhishGuard-X — Training Pipeline"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from layers.ensemble_fusion.ml_model import train_url_model

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  PHISHGUARD-X TRAINING PIPELINE")
    print("="*60 + "\n")
    metrics = train_url_model(n_legit=2000, n_phish=2000,
                               n_features=45, save_dir='models')
    print("\n" + "="*60)
    print(f"  ACCURACY:  {metrics['accuracy']:.4f}")
    print(f"  PRECISION: {metrics['precision']:.4f}")
    print(f"  RECALL:    {metrics['recall']:.4f}")
    print(f"  F1:        {metrics['f1_score']:.4f}")
    print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
    print("="*60 + "\n")
