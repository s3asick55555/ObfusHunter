#!/usr/bin/env python3
"""
Optional helper for ML inference.

This is not required by the web app. You can integrate it later after you have
trained `obfuscation_model.joblib`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd


def predict_obfuscation_class(
    features: Dict[str, Any],
    model_path: str = "obfuscation_model.joblib",
) -> Dict[str, Any]:
    path = Path(model_path)
    if not path.exists():
        return {
            "available": False,
            "reason": "Model file not found. Train one with train_model.py first.",
        }

    bundle = joblib.load(path)
    model = bundle["model"]
    columns = bundle["feature_columns"]

    row = pd.DataFrame([{col: features.get(col, 0) for col in columns}])
    label = model.predict(row)[0]

    result = {
        "available": True,
        "predicted_label": str(label),
    }

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(row)[0]
        classes = model.classes_
        result["probabilities"] = {
            str(cls): float(prob)
            for cls, prob in zip(classes, probabilities)
        }

    return result
