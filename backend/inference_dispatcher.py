"""
Model Inference Dispatcher - Handles method-specific inference
Each model loads its own weights and returns independent results
"""

import os
import time
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Model weight paths - EACH MODEL HAS DIFFERENT WEIGHTS
MODEL_PATHS = {
    "lstm": os.path.join(BASE_DIR, "LSTM", "best_lstm_model.h5"),
    "cnn_lstm": os.path.join(BASE_DIR, "CNN_LSTM", "best_cnn_lstm_model.h5"),
    "transformer": os.path.join(BASE_DIR, "Transformer", "best_transformer_model.h5"),
}

# Model metadata for debugging
MODEL_METADATA = {
    "lstm": {
        "name": "LSTM",
        "version": "1.0",
        "input_shape": (1, 1, 15),
        "description": "Long Short-Term Memory network for sequential pattern detection"
    },
    "cnn_lstm": {
        "name": "CNN-LSTM",
        "version": "1.0", 
        "input_shape": (1, 15, 1),
        "description": "Convolutional + LSTM hybrid for spatial-temporal features"
    },
    "transformer": {
        "name": "Transformer",
        "version": "1.0",
        "input_shape": (1, 15, 1),
        "description": "Attention-based model for global pattern recognition"
    }
}

# Cached model instances
_loaded_models = {}


def get_model_info(method: str) -> Dict:
    """Get model metadata for debugging"""
    meta = MODEL_METADATA.get(method, {})
    path = MODEL_PATHS.get(method, "")
    return {
        "model_name": meta.get("name", method),
        "model_version": meta.get("version", "unknown"),
        "weight_path": path,
        "weight_exists": os.path.exists(path),
        "input_shape": meta.get("input_shape"),
        "description": meta.get("description", "")
    }


def load_model(method: str):
    """Load model by method name - each has its own weights"""
    global _loaded_models
    
    if method in _loaded_models:
        return _loaded_models[method]
    
    path = MODEL_PATHS.get(method)
    if not path or not os.path.exists(path):
        print(f"[MODEL LOAD] {method}: Weight file not found at {path}")
        return None
    
    try:
        from tensorflow import keras
        print(f"[MODEL LOAD] {method}: Loading from {path}")
        model = keras.models.load_model(path)
        _loaded_models[method] = model
        print(f"[MODEL LOAD] {method}: Success! Input shape: {model.input_shape}")
        return model
    except Exception as e:
        print(f"[MODEL LOAD] {method}: FAILED - {e}")
        return None


def run_single_model_inference(
    method: str,
    features_vector: List[float],
    filename: str
) -> Dict:
    """
    Run inference on a SINGLE model and return its unique result
    
    Args:
        method: "lstm", "cnn_lstm", or "transformer"
        features_vector: Preprocessed feature vector
        filename: Original filename
    
    Returns:
        Model-specific result with verdict, score, confidence, evidence
    """
    start_time = time.time()
    model_info = get_model_info(method)
    
    print(f"\n[INFERENCE] ========== {method.upper()} ==========")
    print(f"[INFERENCE] Model: {model_info['model_name']} v{model_info['model_version']}")
    print(f"[INFERENCE] Weights: {model_info['weight_path']}")
    print(f"[INFERENCE] Input length: {len(features_vector)}")
    
    # Try TensorFlow model first
    model = load_model(method)
    raw_score = None
    used_tf = False
    
    if model is not None:
        try:
            # Prepare input based on model's expected shape
            features_15 = features_vector[:15] if len(features_vector) >= 15 else features_vector + [0.0] * (15 - len(features_vector))
            
            if method == "lstm":
                # LSTM expects (batch, 1, 15)
                input_data = np.array([features_15]).astype('float32').reshape(1, 1, 15)
            else:
                # CNN-LSTM and Transformer expect (batch, 15, 1)
                input_data = np.array([features_15]).astype('float32').reshape(1, 15, 1)
            
            prediction = model.predict(input_data, verbose=0)
            raw_score = float(prediction[0][0])
            used_tf = True
            
            print(f"[INFERENCE] TensorFlow prediction: {raw_score:.6f}")
            
        except Exception as e:
            print(f"[INFERENCE] TensorFlow failed: {e}")
            raw_score = None
    
    # Fallback to feature-based analysis if TF failed
    if raw_score is None:
        raw_score = _feature_based_score(features_vector, method)
        print(f"[INFERENCE] Feature-based score: {raw_score:.6f}")
    
    # Calibrate score to risk_score (0-100)
    risk_score = _calibrate_score(raw_score, method)
    
    # Determine verdict
    if risk_score >= 70:
        verdict = "MALICIOUS"
    elif risk_score >= 40:
        verdict = "SUSPICIOUS"
    elif risk_score >= 0:
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"
    
    # Calculate confidence
    confidence = _calculate_confidence(raw_score, used_tf)
    
    inference_time = time.time() - start_time
    
    print(f"[INFERENCE] Raw score: {raw_score:.6f}")
    print(f"[INFERENCE] Risk score: {risk_score}")
    print(f"[INFERENCE] Verdict: {verdict}")
    print(f"[INFERENCE] Confidence: {confidence:.2f}")
    print(f"[INFERENCE] Time: {inference_time:.3f}s")
    print(f"[INFERENCE] Used TensorFlow: {used_tf}")
    
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "raw_score": raw_score,
        "evidence": _generate_evidence(features_vector, raw_score, method),
        "debug": {
            "model_name": model_info["model_name"],
            "model_version": model_info["model_version"],
            "weight_path": model_info["weight_path"],
            "used_tensorflow": used_tf,
            "input_length": len(features_vector),
            "inference_time_ms": round(inference_time * 1000, 2)
        }
    }


def run_all_models_inference(
    features_vector: List[float],
    filename: str,
    parallel: bool = True
) -> Dict[str, Dict]:
    """Run inference on ALL 3 models and return separate results
    
    Args:
        features_vector: Preprocessed feature vector
        filename: Original filename
        parallel: If True, run models concurrently (faster). Default True.
    """
    methods = ["lstm", "cnn_lstm", "transformer"]
    
    if parallel:
        # PARALLEL EXECUTION - Much faster for quick scan
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import time
        
        start_time = time.time()
        results = {}
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Submit all 3 models simultaneously
            future_to_method = {
                executor.submit(run_single_model_inference, method, features_vector, filename): method
                for method in methods
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_method):
                method = future_to_method[future]
                try:
                    results[method] = future.result()
                except Exception as e:
                    print(f"[PARALLEL] {method} failed: {e}")
                    results[method] = {
                        "verdict": "UNKNOWN",
                        "risk_score": 0,
                        "confidence": 0,
                        "error": str(e)
                    }
        
        total_time = time.time() - start_time
        print(f"[PARALLEL] All 3 models completed in {total_time:.3f}s")
        return results
    else:
        # Sequential execution (legacy)
        results = {}
        for method in methods:
            results[method] = run_single_model_inference(method, features_vector, filename)
        return results


def run_quick_inference(
    features_vector: List[float],
    filename: str
) -> Dict[str, Any]:
    """
    QUICK SCAN: Run all 3 models in parallel and return aggregated result
    
    This is optimized for speed - uses parallel execution and returns
    a combined verdict based on majority voting.
    """
    import time
    start_time = time.time()
    
    # Run all models in parallel
    all_results = run_all_models_inference(features_vector, filename, parallel=True)
    
    # Aggregate results using weighted voting
    verdicts = []
    risk_scores = []
    confidences = []
    
    for method, result in all_results.items():
        verdicts.append(result.get("verdict", "UNKNOWN"))
        risk_scores.append(result.get("risk_score", 0))
        confidences.append(result.get("confidence", 0.5))
    
    # Majority voting for verdict
    from collections import Counter
    verdict_counts = Counter(verdicts)
    final_verdict = verdict_counts.most_common(1)[0][0]
    
    # Weighted average for risk score (by confidence)
    total_conf = sum(confidences) or 1
    weighted_risk = sum(r * c for r, c in zip(risk_scores, confidences)) / total_conf
    
    # Average confidence
    avg_confidence = sum(confidences) / len(confidences)
    
    total_time = time.time() - start_time
    
    return {
        "verdict": final_verdict,
        "risk_score": int(weighted_risk),
        "confidence": round(avg_confidence, 2),
        "model_results": all_results,
        "aggregation": {
            "method": "majority_vote_weighted",
            "verdict_distribution": dict(verdict_counts),
            "individual_scores": {m: r.get("risk_score", 0) for m, r in all_results.items()}
        },
        "timing": {
            "total_ms": round(total_time * 1000, 2),
            "parallel": True
        }
    }


def _feature_based_score(features_vector: List[float], method: str) -> float:
    """
    Calculate malware score using DISTINCT logic for each model type.
    This simulates how different architectures perceive the same file features.
    
    Args:
        features_vector: Preprocessed feature list [entropy_norm, size_norm, suspicious_norm, is_pe, is_exe, ...]
        method: Model architecture name
    
    Returns:
        Probability score (0.0 - 1.0)
    """
    if len(features_vector) < 5:
        return 0.05
    
    # Extract raw normalized features
    # Vector indices based on utils.preprocess_for_model
    entropy_norm = features_vector[0]        # 0.0 - 1.0 (mapped from 0-8)
    size_norm = features_vector[1]           # 0.0 - 1.0 (mapped from 0-10MB)
    suspicious_norm = features_vector[2]     # 0.0 - 1.0 (density of keywords)
    is_pe = features_vector[3]               # 0.0 or 1.0
    
    # --- MODEL 1: LSTM (Long Short-Term Memory) ---
    # Philosophy: Focus on SEQUENTIAL patterns. 
    # Logic: High sensitivity to "Suspicious Strings" (sequences of bytes) and PE structure.
    # Weakness: Can miss packed malware if strings are hidden (low entropy sensitivity).
    if method == "lstm":
        base_score = 0.0
        
        # 1. Sequence Analysis (Simulated via suspicious strings density)
        # LSTM detects malicious sequences like "Invoke-Expression" or ransom notes
        if suspicious_norm > 0.05: 
            base_score += suspicious_norm * 0.8  # Strong reaction to strings
        
        # 2. Structural Context
        if is_pe > 0.5:
            base_score += 0.2  # PE files are inherently riskier for LSTM trained on binaries
            
        # 3. Penalize high entropy (LSTM struggles with random/packed sequences)
        # If entropy is very high, LSTM might be confused (lower score confidence)
        if entropy_norm > 0.9: 
            base_score *= 0.8 
            
        return min(0.99, base_score)

    # --- MODEL 2: CNN-LSTM (Spatial + Sequential) ---
    # Philosophy: Focus on SPATIAL patterns (Image-like features) + Local Sequences.
    # Logic: High sensitivity to ENTROPY distribution (packed sections look like noise blocks)
    #        and structural layout (PE headers).
    elif method == "cnn_lstm":
        base_score = 0.0
        
        # 1. Spatial Analysis (Simulated via Entropy)
        # Packed malware has high entropy blocks which CNN detects well
        if entropy_norm > 0.85:
            base_score += 0.6  # High alert for packed files
        elif entropy_norm > 0.6:
            base_score += 0.3
            
        # 2. Hybrid Feature Check
        # Balance between strings and structure
        if suspicious_norm > 0.2:
            base_score += 0.3
            
        if is_pe > 0.5:
            base_score += 0.1
            
        # CNNs are robust; size validates the "image" content
        if size_norm < 0.01: # Too small to have valid structure
             base_score *= 0.5
             
        return min(0.99, base_score)

    # --- MODEL 3: Transformer (Self-Attention / Global Context) ---
    # Philosophy: Focus on GLOBAL RELATIONSHIPS and ANOMALIES.
    # Logic: Can detect subtle correlations. e.g., Low entropy BUT contains specific API calls.
    #        Or High entropy BUT valid header structure.
    elif method == "transformer":
        base_score = 0.0
        
        # 1. Contextual Anomaly Detection
        # High entropy is suspicious ONLY if it's PE.
        if is_pe > 0.5 and entropy_norm > 0.85:
            base_score += 0.95  # Almost certainly packed malware
        elif is_pe > 0.5:
            base_score += 0.1   # Standard PE base risk
            
        # 2. Attention to "Key" token indicators (Strings)
        if suspicious_norm > 0.1:
            base_score += suspicious_norm * 0.6
            
        # 3. Size Context
        # Extremely small PE files are often stagers/downloaders
        if is_pe > 0.5 and size_norm < 0.05: # < 500KB
            base_score += 0.2
            
        return min(0.99, base_score)

    # Fallback
    return 0.0


def _calibrate_score(raw_score: float, method: str) -> int:
    """Calibrate raw probability to risk score 0-100 based on model personality"""
    if method == "lstm":
        # LSTM is conservative: needs strong signal to flag High Risk
        # 0.5 -> 40, 0.8 -> 85
        if raw_score < 0.2: return int(raw_score * 100)
        return int(min(100, raw_score * 100 * 1.1)) # Boost high scores slightly
        
    elif method == "cnn_lstm":
        # CNN is aggressive on packed files: steep curve
        # 0.6 -> 75
        return int(min(100, raw_score ** 0.5 * 100))
        
    elif method == "transformer":
        # Transformer is precise: linear mapping but high threshold
        return int(raw_score * 100)
    
    return int(raw_score * 100)


def _calculate_confidence(raw_score: float, used_tf: bool) -> float:
    """Calculate confidence based on score extremity and model type"""
    # Confidence is higher when score is far from 0.5 (more certain)
    certainty = abs(raw_score - 0.5) * 2  # 0 at 0.5, 1 at 0 or 1
    
    if used_tf:
        base_confidence = 0.7
    else:
        base_confidence = 0.5
    
    return min(0.99, base_confidence + certainty * 0.25)


def _generate_evidence(features_vector: List[float], raw_score: float, method: str) -> List[Dict]:
    """Generate evidence list based on features"""
    evidence = []
    
    if len(features_vector) >= 5:
        entropy = features_vector[0] * 8.0
        suspicious_norm = features_vector[2]
        is_pe = features_vector[3]
        
        if entropy > 7.0:
            evidence.append({
                "type": "entropy",
                "location": "file_content",
                "reason": f"High entropy ({entropy:.2f}) - possible encryption/packing",
                "score": min(1.0, entropy / 8.0),
                "snippet": ""
            })
        
        if suspicious_norm > 0.3:
            evidence.append({
                "type": "strings",
                "location": "file_content",
                "reason": "Suspicious strings detected (ransomware keywords)",
                "score": suspicious_norm,
                "snippet": ""
            })
        
        if is_pe > 0.5:
            evidence.append({
                "type": "pe_header",
                "location": "offset_0",
                "reason": "PE executable format detected",
                "score": 0.3,
                "snippet": "MZ header"
            })
    
    return evidence
