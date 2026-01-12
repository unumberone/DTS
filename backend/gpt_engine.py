"""
GPT Engine - AI-Powered Malware Analysis
Runs IN PARALLEL with local ML models (LSTM, CNN-LSTM, Transformer)
Provides intelligent analysis and combines with ML results for final verdict
"""

import os
import json
import time
from typing import Dict, List, Any

def analyze_with_gpt(
    filename: str, 
    file_size: int, 
    file_type: str, 
    features: dict, 
    local_results: dict = None,
    file_bytes: bytes = None
) -> dict:
    """
    Send file metadata and extracted features to GPT for intelligent analysis.
    This runs IN PARALLEL with local ML models.
    
    Args:
        filename: Name of the file
        file_size: Size in bytes
        file_type: Detected file type (pe_executable, pdf, etc.)
        features: Extracted features (entropy, strings, etc.)
        local_results: Results from ML models (may be None if running parallel)
        file_bytes: Raw file bytes for content analysis
    
    Returns:
        Dict with verdict, risk_score, explanation, confidence
    """
    try:
        from openai import OpenAI
    except ImportError:
        return {
            "verdict": "UNKNOWN",
            "risk_score": 0,
            "confidence": 0.5,
            "explanation": "OpenAI library not installed"
        }
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {
            "verdict": "UNKNOWN",
            "risk_score": 0,
            "confidence": 0.5,
            "explanation": "No OpenAI API Key configured"
        }

    start_time = time.time()
    client = OpenAI(api_key=api_key)

    # ===== DETAILED CONTENT ANALYSIS =====
    content_analysis = {
        "filename": filename,
        "size_bytes": file_size,
        "file_type": file_type,
    }
    
    # Extract entropy (key malware indicator)
    entropy = features.get('entropy', 0)
    content_analysis["entropy"] = f"{entropy:.2f}/8.0"
    content_analysis["entropy_assessment"] = (
        "HIGH (packed/encrypted)" if entropy > 7.0 else
        "MEDIUM" if entropy > 5.0 else
        "LOW (normal)"
    )
    
    # Extract suspicious strings
    suspicious_strings = features.get('strings', [])
    if isinstance(suspicious_strings, list) and len(suspicious_strings) > 0:
        content_analysis["suspicious_strings_found"] = len(suspicious_strings)
        content_analysis["sample_strings"] = suspicious_strings[:10]
    else:
        content_analysis["suspicious_strings_found"] = features.get('suspicious_count', 0)
    
    # Check PE characteristics
    is_pe = features.get('is_pe', 0)
    is_exe = features.get('is_exe', 0)
    content_analysis["is_executable"] = bool(is_pe or is_exe)
    
    # Extract readable strings from file content
    if file_bytes and len(file_bytes) < 500000:  # Only for files < 500KB
        try:
            # Extract ASCII strings (min 6 chars)
            import re
            ascii_strings = re.findall(b'[\x20-\x7e]{6,}', file_bytes[:50000])
            readable = [s.decode('ascii', errors='ignore') for s in ascii_strings[:30]]
            
            # Look for suspicious patterns
            suspicious_patterns = [
                'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet', 'payment',
                'locked', 'AES', 'RSA', 'CryptoAPI', 'cmd.exe', 'powershell',
                'reg add', 'vssadmin', 'shadow', 'delete', 'wmic', 'bcdedit',
                'recovery', 'disable', 'net stop', 'taskkill', '.onion'
            ]
            
            found_suspicious = []
            for s in readable:
                s_lower = s.lower()
                for pattern in suspicious_patterns:
                    if pattern.lower() in s_lower:
                        found_suspicious.append(s[:100])  # Limit length
                        break
            
            if found_suspicious:
                content_analysis["detected_suspicious_patterns"] = found_suspicious[:10]
                content_analysis["pattern_risk"] = "HIGH" if len(found_suspicious) > 5 else "MEDIUM"
            
            # Add some readable strings for context
            content_analysis["sample_readable_strings"] = readable[:15]
            
        except Exception as e:
            content_analysis["content_extraction_error"] = str(e)
    
    # Include ML model results if available (when running after models)
    if local_results:
        content_analysis["ml_model_scores"] = {
            k: {"verdict": v.get("verdict"), "risk_score": v.get("risk_score", 0)}
            for k, v in local_results.items() if isinstance(v, dict) and "verdict" in v
        }

    # ===== BUILD GPT PROMPT =====
    prompt = f"""You are an expert Malware Analyst AI. Analyze this file scan report in detail:

{json.dumps(content_analysis, indent=2, default=str)}

ANALYSIS TASK:
1. Evaluate the risk based on entropy, suspicious strings, and file characteristics
2. Consider the file type - executables are higher risk than documents
3. Look for known malware patterns in the strings
4. Provide a technical verdict

IMPORTANT GUIDELINES:
- High entropy (>7.0) in executables often indicates packing/encryption (suspicious)
- High entropy in PDFs/archives is NORMAL
- Ransomware typically has: encryption APIs, bitcoin/wallet strings, recovery commands
- Look for PowerShell, cmd.exe, vssadmin (shadow copy deletion)

Return ONLY valid JSON:
{{
    "verdict": "CLEAN" or "SUSPICIOUS" or "MALICIOUS",
    "risk_score": 0-100,
    "confidence": 0.0-1.0,
    "explanation": "Brief technical explanation (2-3 sentences)",
    "key_findings": ["finding1", "finding2", ...]
}}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Fast and cost-effective
            messages=[
                {
                    "role": "system", 
                    "content": "You are a cybersecurity expert AI specialized in malware analysis. Analyze files and return JSON verdicts. Be accurate but cautious - false negatives are worse than false positives for security."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,  # Lower for more consistent results
            max_tokens=300,
            response_format={"type": "json_object"}
        )
        
        content = response.choices[0].message.content
        result = json.loads(content)
        
        # Ensure required fields
        result.setdefault("verdict", "UNKNOWN")
        result.setdefault("risk_score", 0)
        result.setdefault("confidence", 0.7)
        result.setdefault("explanation", "AI analysis complete")
        result.setdefault("key_findings", [])
        
        # Add timing info
        elapsed = (time.time() - start_time) * 1000
        result["inference_time_ms"] = round(elapsed, 2)
        result["model"] = "GPT-4o-mini"
        
        print(f"[GPT] Analysis complete: {result['verdict']} ({result['risk_score']}) in {elapsed:.0f}ms")
        return result
        
    except Exception as e:
        error_msg = str(e)
        print(f"[GPT] Analysis failed: {error_msg}")
        
        # Handle specific error types with user-friendly messages
        if "insufficient_quota" in error_msg or "429" in error_msg:
            explanation = "⚠️ OpenAI API quota exceeded. GPT analysis skipped. Results are from 3 ML models only."
            status = "QUOTA_EXCEEDED"
        elif "invalid_api_key" in error_msg or "401" in error_msg:
            explanation = "⚠️ Invalid API key. GPT analysis skipped."
            status = "INVALID_KEY"
        elif "rate_limit" in error_msg:
            explanation = "⚠️ Rate limit reached. GPT analysis skipped."
            status = "RATE_LIMITED"
        else:
            explanation = f"⚠️ GPT unavailable: {error_msg[:100]}"
            status = "ERROR"
        
        return {
            "verdict": "SKIPPED",  # Special status to indicate GPT was skipped
            "risk_score": 0,
            "confidence": 0,
            "explanation": explanation,
            "key_findings": [],
            "model": "GPT-4o-mini",
            "status": status,
            "available": False
        }


def aggregate_all_verdicts(
    lstm_result: dict,
    cnn_lstm_result: dict, 
    transformer_result: dict,
    gpt_result: dict,
    rule_result: dict = None
) -> dict:
    """
    Combine verdicts from all 4 AI sources + rules to produce final verdict.
    Uses weighted voting with confidence scores.
    
    Weights:
    - GPT (AI): 30% - High reasoning capability
    - CNN-LSTM: 25% - Best for spatial-temporal patterns
    - Transformer: 20% - Good for global context
    - LSTM: 15% - Sequential pattern detection
    - Rules: 10% - Signature matching
    
    Returns final verdict with aggregation details.
    """
    
    # Check if GPT is available (not skipped due to quota/error)
    gpt_available = (
        gpt_result and 
        isinstance(gpt_result, dict) and 
        gpt_result.get("verdict") != "SKIPPED" and
        gpt_result.get("available", True) != False
    )
    
    # Define weights - redistribute GPT weight to other models if GPT unavailable
    if gpt_available:
        weights = {
            "gpt": 0.30,
            "cnn_lstm": 0.25,
            "transformer": 0.20,
            "lstm": 0.15,
            "rules": 0.10
        }
    else:
        # GPT unavailable - redistribute weight to ML models
        print("[ENSEMBLE] GPT unavailable, using 3 ML models + Rules only")
        weights = {
            "cnn_lstm": 0.35,      # 25% + 10% from GPT
            "transformer": 0.30,   # 20% + 10% from GPT
            "lstm": 0.25,          # 15% + 10% from GPT
            "rules": 0.10
        }
    
    # Collect all results (exclude GPT if not available)
    all_results = {
        "lstm": lstm_result,
        "cnn_lstm": cnn_lstm_result,
        "transformer": transformer_result,
    }
    if gpt_available:
        all_results["gpt"] = gpt_result
    if rule_result:
        all_results["rules"] = rule_result
    
    # Map verdicts to scores
    def verdict_to_score(v):
        v_upper = str(v).upper()
        if v_upper in ["MALICIOUS", "CRYPTO-RANSOMWARE", "LOCKER-RANSOMWARE", "WIPER", "SCAREWARE"]:
            return 1.0
        elif v_upper in ["SUSPICIOUS"]:
            return 0.5
        elif v_upper in ["CLEAN", "BENIGN", "SAFE"]:
            return 0.0
        else:
            return 0.25  # Unknown -> slightly suspicious
    
    # Calculate weighted score
    total_weight = 0
    weighted_score = 0
    verdict_counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0}
    individual_scores = {}
    
    for source, result in all_results.items():
        if not result or not isinstance(result, dict):
            continue
            
        verdict = result.get("verdict", "UNKNOWN")
        risk_score = result.get("risk_score", 0)
        confidence = result.get("confidence", 0.7)
        
        # Normalize risk_score to 0-1
        if risk_score > 1:
            risk_score = risk_score / 100.0
        
        # Use risk_score directly, weighted by confidence
        source_score = risk_score * confidence
        weight = weights.get(source, 0.1)
        
        weighted_score += source_score * weight
        total_weight += weight
        
        # Count verdicts for majority voting
        v_upper = str(verdict).upper()
        if v_upper in ["MALICIOUS", "CRYPTO-RANSOMWARE", "LOCKER-RANSOMWARE", "WIPER", "SCAREWARE"]:
            verdict_counts["MALICIOUS"] += 1
        elif v_upper == "SUSPICIOUS":
            verdict_counts["SUSPICIOUS"] += 1
        else:
            verdict_counts["CLEAN"] += 1
        
        individual_scores[source] = {
            "verdict": verdict,
            "risk_score": result.get("risk_score", 0),
            "contribution": round(source_score * weight * 100, 2)
        }
    
    # Normalize final score
    if total_weight > 0:
        final_score = weighted_score / total_weight
    else:
        final_score = 0
    
    # Determine final verdict using STRICT thresholds
    # Require STRONG consensus or high weighted score
    malicious_votes = verdict_counts["MALICIOUS"]
    suspicious_votes = verdict_counts["SUSPICIOUS"]
    clean_votes = verdict_counts["CLEAN"]
    total_votes = malicious_votes + suspicious_votes + clean_votes
    
    # STRICT THRESHOLDS (aligned with rule engine):
    # MALICIOUS: majority (3+) OR weighted score >= 70%
    # SUSPICIOUS: 2+ suspicious OR weighted score 35-70%
    # CLEAN: otherwise
    
    if malicious_votes >= 3:
        # Clear majority agrees = MALICIOUS
        final_verdict = "MALICIOUS"
    elif final_score >= 0.70:
        # High weighted score = MALICIOUS
        final_verdict = "MALICIOUS"
    elif malicious_votes >= 2 and final_score >= 0.50:
        # 2 malicious + moderate score = MALICIOUS
        final_verdict = "MALICIOUS"
    elif final_score >= 0.35 or suspicious_votes >= 2:
        # Moderate concern = SUSPICIOUS
        final_verdict = "SUSPICIOUS"
    elif malicious_votes >= 1 and final_score >= 0.25:
        # Single malicious vote with some evidence = SUSPICIOUS
        final_verdict = "SUSPICIOUS"
    else:
        final_verdict = "CLEAN"
    
    # Convert to 0-100 scale
    final_risk_score = int(final_score * 100)
    
    # Calculate overall confidence (average of individual confidences)
    confidences = [r.get("confidence", 0.7) for r in all_results.values() if isinstance(r, dict)]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.7
    
    return {
        "verdict": final_verdict,
        "risk_score": final_risk_score,
        "confidence": round(avg_confidence, 2),
        "aggregation_method": "weighted_vote_ensemble",
        "weights_used": weights,
        "verdict_distribution": verdict_counts,
        "individual_scores": individual_scores,
        "details": f"Ensemble: {malicious_votes} malicious, {suspicious_votes} suspicious, {clean_votes} clean votes"
    }
