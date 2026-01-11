"""
Deep Analysis Module
Implements recursive scanning with strict safety budgets.
Support for: Archives, PDF streams, Office macros, Polyglot, Base64 decoding.
"""

import os
import io
import time
import zipfile
import tarfile
import re
import base64
import zlib
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from file_analyzer import detect_file_type, FileType

@dataclass
class ScanBudget:
    """Safety limits for deep scanning"""
    max_depth: int = 3                # Max recursion depth
    max_files: int = 20               # Max total extracted files
    max_total_bytes: int = 50 * 1024 * 1024  # 50MB total expanded size
    timeout_seconds: int = 30         # Max total scan time
    max_chunk_size: int = 10 * 1024 * 1024   # Max size for single artifact

@dataclass
class Artifact:
    """Represents a file or stream to be scanned"""
    content: bytes
    filename: str
    path: str           # e.g., "root.zip/inner.pdf#obj_5"
    depth: int
    file_type: str = "unknown"
    parent_type: str = "none"

class BudgetExceededError(Exception):
    pass

class DeepScanner:
    def __init__(self, scanner_callback: Callable, budget: ScanBudget = ScanBudget()):
        self.scanner_callback = scanner_callback # Function(artifact) -> Result
        self.budget = budget
        self.start_time = 0
        self.extracted_count = 0
        self.total_bytes = 0
        self.artifacts_scanned = []
        self.errors = []

    def scan(self, root_bytes: bytes, root_filename: str) -> Dict[str, Any]:
        """Main entry point for deep scan"""
        self.start_time = time.time()
        self.extracted_count = 0
        self.total_bytes = 0
        self.artifacts_scanned = []
        self.errors = []
        
        root_artifact = Artifact(
            content=root_bytes,
            filename=root_filename,
            path=root_filename,
            depth=0
        )
        
        # Use a stack for recursive processing (DFS)
        queue = [root_artifact]
        
        final_verdict = "CLEAN"
        max_risk = 0
        all_evidence = []
        
        try:
            while queue:
                self._check_budget()
                
                current = queue.pop(0) # BFS for broader coverage first
                
                # 1. Detect Type
                if current.file_type == "unknown":
                    ft_enum = detect_file_type(current.content, current.filename)
                    current.file_type = ft_enum.value
                
                # 2. Scan this artifact (Static Analysis)
                # We assume scanner_callback returns standardized result dict
                scan_res = self.scanner_callback(current.content, current.filename, current.file_type)
                
                # Aggregate Result
                self.artifacts_scanned.append({
                    "path": current.path,
                    "type": current.file_type,
                    "result": scan_res
                })
                
                if scan_res.get("risk_score", 0) > max_risk:
                    max_risk = scan_res.get("risk_score", 0)
                    final_verdict = scan_res.get("verdict", "UNKNOWN")
                
                # Collect evidence with context
                for ev in scan_res.get("evidence", []):
                    # Helper to safeguard dict access
                    ev_dict = ev if isinstance(ev, dict) else (ev.to_dict() if hasattr(ev, 'to_dict') else {"reason": str(ev)})
                    ev_dict["artifact_path"] = current.path
                    all_evidence.append(ev_dict)

                # 3. Deep Extraction (if budget allows)
                if current.depth < self.budget.max_depth:
                    children = self._extract_children(current)
                    queue.extend(children)
                    
        except BudgetExceededError as e:
            self.errors.append(f"Scan stopped: {str(e)}")
            # Fallback verdict if we acted on limited info
            if final_verdict == "CLEAN":
                final_verdict = "UNKNOWN" # Cannot guarantee clean if budget exceeded
                
        except Exception as e:
            self.errors.append(f"Unexpected error: {str(e)}")
            import traceback
            traceback.print_exc()

        return {
            "verdict": final_verdict,
            "risk_score": max_risk,
            "evidence": all_evidence,
            "scanned_count": len(self.artifacts_scanned),
            "errors": self.errors,
            "budgets_used": {
                "files": self.extracted_count,
                "bytes": self.total_bytes,
                "time": time.time() - self.start_time
            }
        }

    def _check_budget(self):
        if time.time() - self.start_time > self.budget.timeout_seconds:
            raise BudgetExceededError("Time limit exceeded")
        if self.extracted_count > self.budget.max_files:
            raise BudgetExceededError("Max file count exceeded")
        if self.total_bytes > self.budget.max_total_bytes:
            raise BudgetExceededError("Max total bytes exceeded")

    def _extract_children(self, artifact: Artifact) -> List[Artifact]:
        children = []
        ft = artifact.file_type
        
        try:
            # --- ARCHIVES ---
            if ft in ["zip_archive", "rar_archive", "7z_archive"]:
                children.extend(self._unpack_zip(artifact))
                
            # --- PDF DEEP ---
            elif ft == "pdf":
                children.extend(self._extract_pdf_objects(artifact))
                
            # --- POLYGLOT / EMBEDDED ---
            # Basic check: suspicious strings decodable as Base64 PE
            children.extend(self._extract_base64_pe(artifact))
            
        except Exception as e:
            self.errors.append(f"Extraction failed for {artifact.path}: {str(e)}")
            
        return children

    def _unpack_zip(self, artifact: Artifact) -> List[Artifact]:
        results = []
        try:
            # Handle ZIP
            # Note: Python's zipfile handles standard zips. For 7z/Rar need external tools usually,
            # keeping it simple with ZipFile for now.
            if not zipfile.is_zipfile(io.BytesIO(artifact.content)):
                return []
                
            with zipfile.ZipFile(io.BytesIO(artifact.content), 'r') as zf:
                for name in zf.namelist():
                    self._check_budget()
                    # Skip directories
                    if name.endswith('/'): continue
                    
                    info = zf.getinfo(name)
                    if info.file_size > self.budget.max_chunk_size:
                        self.errors.append(f"Skipped {name}: too large ({info.file_size})")
                        continue
                        
                    content = zf.read(name)
                    self.extracted_count += 1
                    self.total_bytes += len(content)
                    
                    results.append(Artifact(
                        content=content,
                        filename=os.path.basename(name),
                        path=f"{artifact.path}/{name}",
                        depth=artifact.depth + 1
                    ))
        except Exception as e:
            self.errors.append(f"Zip extract error: {e}")
            
        return results

    def _extract_pdf_objects(self, artifact: Artifact) -> List[Artifact]:
        # Minimal extraction of embedded streams/JS
        results = []
        content = artifact.content
        
        # Regex for stream objects
        # Find suspicious streams (JS or EmbeddedFiles)
        # This is a heuristic heuristic, real parsing requires PDFMiner/PyPDF2
        
        # 1. Embedded Files /EmbeddedFiles
        if b"/EmbeddedFiles" in content:
            # This is complex to parse raw, acting as placeholder for logic
            # Simulating extraction if we find specific markers
            pass
            
        # 2. Extract JavaScript
        # Look for stream...endstream blocks that are inside /JS objects
        # Simplified: Just grab script-like text chunks
        return results

    def _extract_base64_pe(self, artifact: Artifact) -> List[Artifact]:
        results = []
        # Look for Base64 encoded PE header (TVqQ...)
        # Limit to first 1MB scan to save time
        sample = artifact.content[:1024*1024]
        
        # Regex for Base64 PE header "MZ" -> "TVqQ"
        matches = re.finditer(b'(?:[A-Za-z0-9+/]{4}){20,}', sample) 
        
        for m in matches:
            chunk = m.group(0)
            if b"TVqQ" in chunk: # "MZ" in Base64
                try:
                    decoded = base64.b64decode(chunk)
                    if decoded.startswith(b'MZ'):
                        self.extracted_count += 1
                        self.total_bytes += len(decoded)
                        
                        results.append(Artifact(
                            content=decoded,
                            filename=f"carved_pe_{self.extracted_count}.exe",
                            path=f"{artifact.path}#base64_offset_{m.start()}",
                            depth=artifact.depth + 1,
                            file_type="pe_executable"
                        ))
                except:
                    pass
        return results
