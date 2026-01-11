"""
Hybrid Analysis Engine v2.0
Integrates:
1. File Type Routing (Magic Bytes)
2. Reputation Lists (Whitelist/Blacklist)
3. Rule-based Heuristics (Explainable Scoring)
4. ML Models (via dispatcher)
"""

import os
import json
import re
import math
import hashlib
from typing import Dict, List, Any, Optional
from enum import Enum
import file_analyzer  # Reuse existing detectors
from file_analyzer import FileType, detect_file_type
from inference_dispatcher import run_single_model_inference, run_all_models_inference, run_quick_inference

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

class AnalysisMethod(str, Enum):
    RULE_ONLY = "rule_only"
    LIST_ONLY = "list_only"
    HYBRID = "hybrid"  # Default & Most Strict
    LSTM = "lstm"
    CNNLSTM = "cnn_lstm"
    TRANSFORMER = "transformer"
    ALL = "all"

class HybridEngine:
    def __init__(self):
        self.lists = self._load_json("reputation.json")
        self.rules_config = self._load_json("rules.json")
        self.rules = self.rules_config.get("rules", [])
        print(f"[HYBRID] Loaded {len(self.rules)} rules and reputation lists")

    def _load_json(self, name):
        try:
            with open(os.path.join(DATA_DIR, name), "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[HYBRID] Error loading {name}: {e}")
            return {}

    def analyze(self, file_bytes: bytes, filename: str, method: str, mode: str = "quick") -> Dict[str, Any]:
        """Orchestrate the analysis based on requested method and mode"""
        
        # 1. Identity & File Type
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        file_type_enum = detect_file_type(file_bytes, filename)
        file_type = file_type_enum.value
        
        # Base result object
        base_result = {
            "file": {
                "name": filename,
                "sha256": sha256,
                "file_type": file_type,
                "size": len(file_bytes)
            },
            "requested": {
                "method": method,
                "mode": mode
            },
            "versions": {
                "rules": self.rules_config.get("version"),
                "lists": self.lists.get("version")
            },
            "results": {},
            "errors": []
        }

        # --- DEEP SCAN MODE ---
        if mode == "deep":
            from deep_analysis import DeepScanner
            print(f"[HYBRID] Starting DEEP scan for {filename}")
            
            # Wrapper to bind method/logic to the scanner callback
            def _scanner_callback(content, fname, ftype):
                # Run standard single-file analysis
                # For deep scan artifacts, we typically rely primarily on RULES + LISTS
                # ML models are expensive to run on 100s of sub-files, so we might skip or selective run
                
                # Analyze as if it's a standalone file
                # But we just return the 'results' part
                res = self._analyze_single_artifact(content, fname, ftype, method)
                
                # Extract the primary verdict object to simplify aggregation
                # Prefer Hybrid or Rule result
                if "hybrid" in res: return res["hybrid"]
                if "rule_only" in res: return res["rule_only"]
                if method in res: return res[method]
                return {"verdict": "UNKNOWN", "risk_score": 0}

            scanner = DeepScanner(_scanner_callback)
            deep_res = scanner.scan(file_bytes, filename)
            
            # Populate results
            # Deep Scan essentially replaces the "Hybrid" view with an aggregated Deep view
            # We map it to "hybrid" or create a specific "deep_static" key
            
            base_result["results"]["deep_static"] = deep_res
            base_result["budgets"] = deep_res.get("budgets_used")
            
            # Also populate 'hybrid' for backward compat in UI
            base_result["results"]["hybrid"] = {
                "verdict": deep_res["verdict"],
                "risk_score": deep_res["risk_score"],
                "evidence": deep_res["evidence"], # Flattened evidence from all files
                "details": f"Deep Scan: {deep_res['scanned_count']} artifacts scanned. Errors: {len(deep_res['errors'])}",
                "source": "Deep Engine"
            }
            
            if deep_res["errors"]:
                base_result["errors"].extend(deep_res["errors"])
                
            return base_result

        # --- QUICK MODE (Standard) ---
        # Quick mode runs ALL 3 models in PARALLEL for speed
        # Then aggregates results using majority voting
        
        if mode == "quick": # Run parallel scan for ANY method when quick mode is selected (method selector acts as 'primary view' filter in UI)
            print(f"[HYBRID] Starting QUICK SCAN (parallel 3 models) for {filename}")
            
            # Get features for ML models
            from utils import extract_features_from_bytes, preprocess_for_model
            raw_feats = extract_features_from_bytes(file_bytes, filename)
            vector = preprocess_for_model(raw_feats, 100)
            
            # Run quick inference (parallel execution of all 3 models)
            quick_result = run_quick_inference(vector, filename)
            
            # Also run rule-based for hybrid combination
            sha256 = hashlib.sha256(file_bytes).hexdigest()
            list_result = self._check_lists(sha256, filename)
            features = self._extract_features(file_bytes, file_type, filename)
            rule_result = self._apply_rules(features, file_type, list_result)
            
            # Combine ML and rule-based results
            # If blacklisted, override ML results
            if list_result["source"] == "blacklist":
                final_verdict = "MALICIOUS"
                final_score = 100
            elif list_result["source"] == "whitelist":
                final_verdict = "CLEAN"
                final_score = 0
            else:
                # Weight: ML 60%, Rules 40%
                ml_score = quick_result["risk_score"]
                rule_score = rule_result["risk_score"]
                final_score = int(ml_score * 0.6 + rule_score * 0.4)
                
                if final_score >= 70:
                    final_verdict = "MALICIOUS"
                elif final_score >= 40:
                    final_verdict = "SUSPICIOUS"
                else:
                    final_verdict = "CLEAN"
            
            base_result["results"] = {
                "hybrid": {
                    "verdict": final_verdict,
                    "risk_score": final_score,
                    "confidence": quick_result["confidence"],
                    "evidence": rule_result.get("evidence", []),
                    "details": f"Quick Scan: 3 models parallel | ML: {quick_result['risk_score']} | Rules: {rule_result['risk_score']}",
                    "source": "Quick Engine (Parallel ML + Rules)"
                },
                "quick_ml": quick_result,
                "rule_only": rule_result,
                "list_only": list_result,
                # Individual model results for detailed view
                "lstm": quick_result["model_results"].get("lstm", {}),
                "cnn_lstm": quick_result["model_results"].get("cnn_lstm", {}),
                "transformer": quick_result["model_results"].get("transformer", {})
            }
            
            base_result["timing"] = quick_result.get("timing", {})
            return base_result
        
        # --- STANDARD MODE (method-specific) ---
        # Perform single artifact analysis based on specific method
        results_map = self._analyze_single_artifact(file_bytes, filename, file_type, method)
        base_result["results"] = results_map
        return base_result

    def _analyze_single_artifact(self, file_bytes: bytes, filename: str, file_type: str, method: str) -> Dict:
        """Core analysis logic for one file content"""
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        
        results = {}
        
        # --- List Check (Phase B) ---
        list_result = self._check_lists(sha256, filename)
        if method == AnalysisMethod.LIST_ONLY:
            results["list_only"] = list_result
            return results

        # --- Rule Check (Phase C) ---
        features = self._extract_features(file_bytes, file_type, filename)
        rule_result = self._apply_rules(features, file_type, list_result)
        
        if method == AnalysisMethod.RULE_ONLY:
            results["rule_only"] = rule_result
            return results

        # --- Hybrid (Most common) ---
        # Calculate hybrid even if method=all
        hybrid_res = self._combine_scores(list_result, rule_result)
        if method == AnalysisMethod.HYBRID or method == AnalysisMethod.ALL:
            results["hybrid"] = hybrid_res

        # --- ML Models ---
        # Run ML if requested OR if method=All
        should_run_ml = (method in [AnalysisMethod.LSTM, AnalysisMethod.CNNLSTM, AnalysisMethod.TRANSFORMER, AnalysisMethod.ALL])
        
        # Only run ML on PE files for now (or force logic)
        # To avoid overhead on image/pdf artifacts during deep scan, we can limit this
        if should_run_ml and file_type == "pe_executable":
            from utils import extract_features_from_bytes, preprocess_for_model
            raw_feats = extract_features_from_bytes(file_bytes, filename)
            vector = preprocess_for_model(raw_feats, 100)
            
            if method == AnalysisMethod.ALL:
                ml_all = run_all_models_inference(vector, filename)
                results.update(ml_all)
            elif method in [AnalysisMethod.LSTM, AnalysisMethod.CNNLSTM, AnalysisMethod.TRANSFORMER]:
                ml_res = run_single_model_inference(method, vector, filename)
                results[method] = ml_res

        # If User requested a specific method that wasn't covered (e.g. list_only was caught early)
        if method == AnalysisMethod.ALL:
            results["list_only"] = list_result
            results["rule_only"] = rule_result

        return results

    def _check_lists(self, sha256: str, filename: str) -> Dict:
        """Phase B: Reputation Lists"""
        res = {"verdict": "UNKNOWN", "risk_score": 0, "source": "none", "details": ""}
        
        # 1. Blacklist
        blacklist = self.lists.get("blacklist", {}).get("hashes", {})
        if sha256 in blacklist:
            entry = blacklist[sha256]
            return {
                "verdict": "MALICIOUS", 
                "risk_score": 100, 
                "source": "blacklist", 
                "details": f"Blocked by reputation: {entry.get('label')}"
            }
            
        # 2. Whitelist
        whitelist = self.lists.get("whitelist", {}).get("hashes", {})
        if sha256 in whitelist:
            entry = whitelist[sha256]
            return {
                "verdict": "CLEAN", 
                "risk_score": 0, 
                "source": "whitelist", 
                "details": f"Trusted: {entry.get('reason')}"
            }
            
        return res

    def _extract_features(self, file_bytes: bytes, file_type: str, filename: str) -> Dict:
        """Extract metadata for Rule Engine"""
        features = {
            "entropy": self._calculate_entropy(file_bytes),
            "size": len(file_bytes),
            "strings": [],
            "metadata": {}
        }
        
        # Simple string extraction (for rule matching)
        try:
            # Extract printable strings > 4 chars
            import re
            text = file_bytes.decode('utf-8', errors='ignore')
            features["strings"] = list(set(re.findall(r"[A-Za-z0-9+/=]{5,}", text)))
        except:
            features["strings"] = []
            
        # Type specific features (Simplified for demo)
        if file_type == "pdf":
            features["metadata"]["pdf_keys"] = []
            if b"/OpenAction" in file_bytes: features["metadata"]["pdf_keys"].append("/OpenAction")
            if b"/JavaScript" in file_bytes: features["metadata"]["pdf_keys"].append("/JavaScript")
            
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _apply_rules(self, features: Dict, file_type: str, list_result: Dict) -> Dict:
        """Phase C: Rule Engine"""
        score = 0
        hits = []
        
        # If Whitelisted, skip rules unless critical (Policy)
        if list_result["source"] == "whitelist":
            return {"verdict": "CLEAN", "risk_score": 0, "evidence": [], "details": "Trusted by Whitelist"}

        # Iterate rules
        for rule in self.rules:
            # Check target scope
            targets = rule.get("target", [])
            if "all" not in targets and file_type not in targets:
                # Map broad categories (pe_executable -> pe)
                if file_type == "pe_executable" and "pe" in targets: pass
                elif file_type == "zip_archive" and "archive" in targets: pass
                elif "unknown" in targets: pass # Apply general rules
                else: continue
                
            # Check logic
            matched = False
            evidence = ""
            
            if rule["type"] == "entropy":
                # Condition e.g. "> 7.2"
                op, val = rule["condition"].split()
                val = float(val)
                ent = features["entropy"]
                if op == ">" and ent > val: matched = True
                evidence = f"Entropy {ent:.2f} > {val}"
                
            elif rule["type"] == "dictionary":
                # Check if any keyword exists in metadata keys or strings
                keywords = rule["match"]
                # Search in keys
                keys = features["metadata"].get("pdf_keys", [])
                found = [k for k in keywords if k in keys]
                if found:
                    matched = True
                    evidence = f"Found keys: {found}"
                    
            elif rule["type"] == "regex" or rule["type"] == "string":
                # Simplified check in extracted strings
                pattern = rule["match"]
                # In real prod, we'd regex the full content or chunks
                # Here we check the 'strings' list roughly
                # TODO: Implement full regex scan
                pass 
                
            if matched:
                score += rule["weight"]
                hits.append({
                    "rule_id": rule["id"],
                    "desc": rule["desc"],
                    "weight": rule["weight"],
                    "evidence": evidence
                })
        
        risk_score = min(100, score)
        
        # Determine verdict
        if risk_score >= 80: verdict = "MALICIOUS"
        elif risk_score >= 40: verdict = "SUSPICIOUS"
        else: verdict = "CLEAN"
        
        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "evidence": hits,
            "details": f"Matched {len(hits)} rules"
        }

    def _combine_scores(self, list_res: Dict, rule_res: Dict) -> Dict:
        """Combine List and Rule results (Hybrid)"""
        
        # 1. Blacklist is absolute
        if list_res["source"] == "blacklist":
            return list_res
            
        # 2. Whitelist acts as dampener
        if list_res["source"] == "whitelist":
            # If Rules detected HIGH CRITICALITY, we might override global whitelist
            # But for now, trust whitelist
            return list_res
            
        # 3. Default to Rule Result
        # Could add bonus if Signed (Greylist/Author list)
        return rule_res

# Singleton
hybrid_engine_instance = HybridEngine()
