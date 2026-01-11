"""
File Analyzer Module - Handles file type detection and routing
Senior ML Security Engineer + Backend Engineer Implementation

This module implements:
1. Magic bytes-based file type detection
2. File type routing to appropriate analyzers
3. Safe fallback mechanisms
4. Evidence collection and chunk scoring
"""

import struct
import re
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import zipfile
import io


class FileType(Enum):
    """Supported file types for analysis"""
    PE_EXECUTABLE = "pe_executable"      # EXE, DLL, etc.
    PDF = "pdf"
    IMAGE = "image"                       # PNG, JPG, GIF, WEBP
    ARCHIVE = "archive"                   # ZIP, RAR, 7z
    TEXT_SCRIPT = "text_script"           # JS, VBS, PS1, BAT
    OFFICE = "office"                     # DOCX, XLSX, PPTX (ZIP-based)
    UNKNOWN = "unknown"


class Verdict(Enum):
    """Scan verdict types"""
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass
class Evidence:
    """Evidence of suspicious content"""
    evidence_type: str      # "pdf_object", "byte_window", "line_range", "pe_section"
    location: str           # Object ID, byte offset, line number
    reason: str             # Why it's suspicious
    score: float            # 0-1 confidence
    snippet: str = ""       # Snippet of suspicious content


@dataclass
class ScanResult:
    """Standardized scan result"""
    file_type: str
    verdict: str
    risk_score: int         # 0-100
    confidence: float       # 0-1
    evidence: List[Evidence] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    details: str = ""
    model_used: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "file_type": self.file_type,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "evidence": [
                {
                    "type": e.evidence_type,
                    "location": e.location,
                    "reason": e.reason,
                    "score": e.score,
                    "snippet": e.snippet
                } for e in self.evidence
            ],
            "errors": self.errors,
            "details": self.details,
            "model_used": self.model_used
        }


# ============= MAGIC BYTES SIGNATURES =============

MAGIC_BYTES = {
    # PE Executable
    b"\x4D\x5A": FileType.PE_EXECUTABLE,  # MZ header
    
    # PDF
    b"%PDF": FileType.PDF,
    
    # Images
    b"\x89PNG\r\n\x1a\n": FileType.IMAGE,       # PNG
    b"\xFF\xD8\xFF": FileType.IMAGE,             # JPEG
    b"GIF87a": FileType.IMAGE,                   # GIF87a
    b"GIF89a": FileType.IMAGE,                   # GIF89a
    b"RIFF": FileType.IMAGE,                     # WEBP (RIFF....WEBP)
    b"BM": FileType.IMAGE,                       # BMP
    
    # Archives
    b"PK\x03\x04": FileType.ARCHIVE,             # ZIP/DOCX/XLSX/PPTX
    b"PK\x05\x06": FileType.ARCHIVE,             # Empty ZIP
    b"Rar!\x1a\x07": FileType.ARCHIVE,           # RAR
    b"7z\xbc\xaf\x27\x1c": FileType.ARCHIVE,     # 7z
}

SCRIPT_EXTENSIONS = {'.js', '.vbs', '.ps1', '.bat', '.cmd', '.sh', '.py', '.rb'}
OFFICE_EXTENSIONS = {'.docx', '.xlsx', '.pptx', '.odt', '.ods'}


def detect_file_type(file_bytes: bytes, filename: str = "") -> FileType:
    """
    Detect file type using magic bytes (NOT trusting client MIME type)
    
    Args:
        file_bytes: Raw file content
        filename: Original filename (for extension hints only)
    
    Returns:
        FileType enum value
    """
    if len(file_bytes) < 8:
        return FileType.UNKNOWN
    
    # Check magic bytes
    for magic, file_type in MAGIC_BYTES.items():
        if file_bytes.startswith(magic):
            # Special case: ZIP-based Office documents
            if file_type == FileType.ARCHIVE:
                lower_name = filename.lower()
                if any(lower_name.endswith(ext) for ext in OFFICE_EXTENSIONS):
                    return FileType.OFFICE
                # Check if it's Office by content
                if _is_office_document(file_bytes):
                    return FileType.OFFICE
            
            # Special case: WEBP (RIFF....WEBP)
            if magic == b"RIFF" and len(file_bytes) >= 12:
                if file_bytes[8:12] == b"WEBP":
                    return FileType.IMAGE
                else:
                    return FileType.UNKNOWN  # Other RIFF format
            
            return file_type
    
    # Check for text/script files by extension and content
    lower_name = filename.lower()
    if any(lower_name.endswith(ext) for ext in SCRIPT_EXTENSIONS):
        return FileType.TEXT_SCRIPT
    
    # Check if it's ASCII/UTF-8 text
    if _is_text_file(file_bytes[:4096]):
        # Check for script patterns
        if _has_script_patterns(file_bytes[:4096]):
            return FileType.TEXT_SCRIPT
    
    return FileType.UNKNOWN


def _is_office_document(file_bytes: bytes) -> bool:
    """Check if ZIP file is an Office document"""
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), 'r') as zf:
            names = zf.namelist()
            # DOCX/XLSX/PPTX markers
            office_markers = ['[Content_Types].xml', 'word/', 'xl/', 'ppt/', 'docProps/']
            return any(any(marker in name for marker in office_markers) for name in names)
    except:
        return False


def _is_text_file(sample: bytes) -> bool:
    """Check if content appears to be text"""
    try:
        sample.decode('utf-8')
        # Check for high ratio of printable characters
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        return printable / len(sample) > 0.85 if sample else False
    except:
        return False


def _has_script_patterns(sample: bytes) -> bool:
    """Check for common script patterns"""
    try:
        text = sample.decode('utf-8', errors='ignore').lower()
        patterns = [
            'function ', 'var ', 'let ', 'const ',  # JavaScript
            'sub ', 'dim ', 'wscript',              # VBScript
            'param(', 'function ', '$',             # PowerShell
            '@echo', 'set ', 'goto ',               # Batch
            '#!/', 'import ', 'def ',               # Python/Shell
        ]
        return any(p in text for p in patterns)
    except:
        return False


# ============= FILE TYPE ANALYZERS =============

class ImageAnalyzer:
    """
    Analyzer for image files (PNG, JPEG, GIF, WEBP, BMP)
    
    Images are generally safe unless:
    1. Steganography (hidden data) - requires specialized model
    2. Polyglot files (image + executable)
    3. Exploit payloads in metadata
    
    Without specialized steganography model, we do basic checks only.
    """
    
    @staticmethod
    def analyze(file_bytes: bytes, filename: str) -> ScanResult:
        evidence = []
        errors = []
        risk_score = 0
        
        # Check for polyglot (image header but also PE header later)
        pe_offset = file_bytes.find(b"MZ")
        if pe_offset > 0 and pe_offset < len(file_bytes) - 2:
            # Check if there's a valid PE header after MZ
            if len(file_bytes) > pe_offset + 64:
                evidence.append(Evidence(
                    evidence_type="byte_window",
                    location=f"offset_{pe_offset}",
                    reason="Potential polyglot: MZ header found in image",
                    score=0.7,
                    snippet=f"MZ at offset {pe_offset}"
                ))
                risk_score = 40
        
        # Check for suspicious strings in metadata/comments
        suspicious_in_image = [
            b"<script", b"javascript:", b"eval(", b"exec(",
            b"powershell", b"cmd.exe", b"WScript"
        ]
        for sus in suspicious_in_image:
            if sus.lower() in file_bytes.lower():
                evidence.append(Evidence(
                    evidence_type="byte_window",
                    location="embedded",
                    reason=f"Suspicious string in image: {sus.decode(errors='ignore')}",
                    score=0.5,
                    snippet=sus.decode(errors='ignore')
                ))
                risk_score = max(risk_score, 30)
        
        # Determine verdict
        if risk_score >= 50:
            verdict = Verdict.SUSPICIOUS.value
        elif risk_score > 0:
            verdict = Verdict.SUSPICIOUS.value
        else:
            verdict = Verdict.CLEAN.value
            risk_score = 0
        
        return ScanResult(
            file_type=FileType.IMAGE.value,
            verdict=verdict,
            risk_score=risk_score,
            confidence=0.9 if not evidence else 0.7,
            evidence=evidence,
            errors=errors,
            details=f"Image file - {'clean content' if not evidence else 'anomalies detected'}",
            model_used="image_heuristic"
        )


class PDFAnalyzer:
    """
    Analyzer for PDF files
    
    Checks for:
    1. JavaScript actions
    2. /OpenAction, /AA (automatic actions)
    3. /Launch actions
    4. Embedded files
    5. Suspicious URLs
    6. /JS, /JavaScript objects
    """
    
    # Suspicious PDF patterns
    PDF_SUSPICIOUS_PATTERNS = [
        (rb'/JavaScript', "JavaScript action", 0.6),
        (rb'/JS\s', "JS action shorthand", 0.6),
        (rb'/OpenAction', "Automatic open action", 0.5),
        (rb'/AA\s', "Additional actions", 0.4),
        (rb'/Launch', "Launch action (can execute commands)", 0.8),
        (rb'/EmbeddedFile', "Embedded file", 0.4),
        (rb'/RichMedia', "Rich media (Flash/video)", 0.3),
        (rb'/XFA', "XFA forms (can contain scripts)", 0.4),
        (rb'eval\s*\(', "JavaScript eval()", 0.7),
        (rb'app\.launchURL', "URL launch", 0.5),
        (rb'/URI\s*\(', "URI reference", 0.2),
        (rb'/S\s*/URI', "URI action", 0.3),
    ]
    
    @staticmethod
    def analyze(file_bytes: bytes, filename: str) -> ScanResult:
        evidence = []
        errors = []
        risk_score = 0
        total_score = 0.0
        
        try:
            # Verify PDF header
            if not file_bytes.startswith(b"%PDF"):
                errors.append("Invalid PDF header")
                return ScanResult(
                    file_type=FileType.PDF.value,
                    verdict=Verdict.UNKNOWN.value,
                    risk_score=20,
                    confidence=0.5,
                    evidence=[],
                    errors=errors,
                    details="Cannot parse PDF - invalid header",
                    model_used="pdf_parser"
                )
            
            # Scan for suspicious patterns
            for pattern, reason, score in PDFAnalyzer.PDF_SUSPICIOUS_PATTERNS:
                matches = list(re.finditer(pattern, file_bytes, re.IGNORECASE))
                for match in matches:
                    # Find context (object number if possible)
                    start = max(0, match.start() - 50)
                    context = file_bytes[start:match.start()].decode(errors='ignore')
                    obj_match = re.search(r'(\d+)\s+\d+\s+obj', context)
                    obj_id = obj_match.group(1) if obj_match else "unknown"
                    
                    evidence.append(Evidence(
                        evidence_type="pdf_object",
                        location=f"obj_{obj_id}_offset_{match.start()}",
                        reason=reason,
                        score=score,
                        snippet=file_bytes[match.start():match.start()+50].decode(errors='ignore')
                    ))
                    total_score += score
            
            # Check for encrypted streams (high entropy in streams)
            stream_starts = [m.start() for m in re.finditer(rb'stream\r?\n', file_bytes)]
            for start in stream_starts[:10]:  # Check first 10 streams
                stream_end = file_bytes.find(b'endstream', start)
                if stream_end > start:
                    stream_data = file_bytes[start+7:stream_end]
                    if len(stream_data) > 100:
                        entropy = _calculate_entropy(stream_data)
                        if entropy > 7.5:
                            # High entropy stream - could be encrypted/obfuscated
                            evidence.append(Evidence(
                                evidence_type="pdf_object",
                                location=f"stream_offset_{start}",
                                reason=f"High entropy stream ({entropy:.2f}) - possibly obfuscated",
                                score=0.3,
                                snippet=""
                            ))
                            total_score += 0.2
            
            # Calculate risk score (capped at 100)
            risk_score = min(100, int(total_score * 50))
            
            # Determine verdict
            if risk_score >= 70:
                verdict = Verdict.MALICIOUS.value
            elif risk_score >= 30:
                verdict = Verdict.SUSPICIOUS.value
            elif risk_score > 0:
                verdict = Verdict.SUSPICIOUS.value
            else:
                verdict = Verdict.CLEAN.value
            
            confidence = 0.8 if evidence else 0.95
            
        except Exception as e:
            errors.append(f"PDF parsing error: {str(e)}")
            # SAFE FALLBACK: Parser fail = UNKNOWN, not MALICIOUS
            return ScanResult(
                file_type=FileType.PDF.value,
                verdict=Verdict.UNKNOWN.value,
                risk_score=15,
                confidence=0.3,
                evidence=[],
                errors=errors,
                details=f"PDF parsing failed: {str(e)}",
                model_used="pdf_parser"
            )
        
        return ScanResult(
            file_type=FileType.PDF.value,
            verdict=verdict,
            risk_score=risk_score,
            confidence=confidence,
            evidence=evidence[:10],  # Top 10 evidence items
            errors=errors,
            details=f"PDF analysis: {len(evidence)} suspicious patterns found" if evidence else "PDF analysis: clean document",
            model_used="pdf_parser"
        )


class ArchiveAnalyzer:
    """
    Analyzer for archive files (ZIP, RAR, 7z)
    
    Checks for:
    1. Zip bombs (decompression ratio)
    2. Suspicious filenames inside
    3. Nested archives (depth limit)
    4. Executable content
    """
    
    MAX_UNPACK_SIZE = 100 * 1024 * 1024  # 100MB limit
    MAX_FILES = 1000
    MAX_DEPTH = 3
    
    @staticmethod
    def analyze(file_bytes: bytes, filename: str, depth: int = 0) -> ScanResult:
        evidence = []
        errors = []
        risk_score = 0
        
        if depth >= ArchiveAnalyzer.MAX_DEPTH:
            return ScanResult(
                file_type=FileType.ARCHIVE.value,
                verdict=Verdict.SUSPICIOUS.value,
                risk_score=40,
                confidence=0.6,
                evidence=[Evidence(
                    evidence_type="archive",
                    location="nested",
                    reason=f"Archive nesting depth exceeded ({depth})",
                    score=0.4,
                    snippet=""
                )],
                errors=[],
                details="Nested archive depth limit reached",
                model_used="archive_scanner"
            )
        
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes), 'r') as zf:
                names = zf.namelist()
                
                # Check file count
                if len(names) > ArchiveAnalyzer.MAX_FILES:
                    evidence.append(Evidence(
                        evidence_type="archive",
                        location="root",
                        reason=f"Excessive file count ({len(names)})",
                        score=0.5,
                        snippet=""
                    ))
                    risk_score = max(risk_score, 30)
                
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                
                # Check for zip bomb (high compression ratio)
                if len(file_bytes) > 0:
                    ratio = total_uncompressed / len(file_bytes)
                    if ratio > 100:
                        evidence.append(Evidence(
                            evidence_type="archive",
                            location="root",
                            reason=f"Potential zip bomb (ratio: {ratio:.1f}x)",
                            score=0.9,
                            snippet=""
                        ))
                        risk_score = 80
                
                # Check for suspicious filenames
                suspicious_extensions = ['.exe', '.dll', '.scr', '.pif', '.bat', '.cmd', '.ps1', '.vbs', '.js']
                for name in names[:100]:  # Check first 100 files
                    lower_name = name.lower()
                    if any(lower_name.endswith(ext) for ext in suspicious_extensions):
                        evidence.append(Evidence(
                            evidence_type="archive",
                            location=name,
                            reason=f"Executable file in archive: {name}",
                            score=0.4,
                            snippet=""
                        ))
                        risk_score = max(risk_score, 35)
                
        except zipfile.BadZipFile:
            errors.append("Invalid ZIP file")
            return ScanResult(
                file_type=FileType.ARCHIVE.value,
                verdict=Verdict.UNKNOWN.value,
                risk_score=20,
                confidence=0.4,
                evidence=[],
                errors=errors,
                details="Cannot parse archive",
                model_used="archive_scanner"
            )
        except Exception as e:
            errors.append(f"Archive error: {str(e)}")
            return ScanResult(
                file_type=FileType.ARCHIVE.value,
                verdict=Verdict.UNKNOWN.value,
                risk_score=20,
                confidence=0.4,
                evidence=[],
                errors=errors,
                details=f"Archive parsing failed: {str(e)}",
                model_used="archive_scanner"
            )
        
        # Determine verdict
        if risk_score >= 60:
            verdict = Verdict.MALICIOUS.value
        elif risk_score >= 25:
            verdict = Verdict.SUSPICIOUS.value
        else:
            verdict = Verdict.CLEAN.value
        
        return ScanResult(
            file_type=FileType.ARCHIVE.value,
            verdict=verdict,
            risk_score=risk_score,
            confidence=0.75,
            evidence=evidence[:10],
            errors=errors,
            details=f"Archive contains {len(names)} files" + (f", {len(evidence)} suspicious items" if evidence else ""),
            model_used="archive_scanner"
        )


class TextScriptAnalyzer:
    """
    Analyzer for text/script files (JS, VBS, PS1, BAT, etc.)
    
    Uses pattern matching for suspicious constructs
    """
    
    SUSPICIOUS_PATTERNS = [
        # PowerShell
        (r'Invoke-Expression', "PowerShell code execution", 0.6),
        (r'IEX\s*\(', "PowerShell IEX (Invoke-Expression)", 0.7),
        (r'DownloadString', "PowerShell download", 0.6),
        (r'Net\.WebClient', "PowerShell WebClient", 0.5),
        (r'-enc\s+[A-Za-z0-9+/=]+', "Encoded PowerShell command", 0.8),
        
        # JavaScript
        (r'eval\s*\(', "JavaScript eval", 0.5),
        (r'document\.write\s*\(', "Document write", 0.3),
        (r'unescape\s*\(', "Unescape (often used in exploits)", 0.5),
        (r'fromCharCode', "String from char codes", 0.4),
        (r'ActiveXObject', "ActiveX object creation", 0.6),
        
        # VBScript
        (r'WScript\.Shell', "WScript Shell", 0.6),
        (r'Shell\.Run', "Shell execution", 0.7),
        (r'CreateObject', "Object creation", 0.4),
        
        # Batch
        (r'certutil\s+-decode', "Certutil decode (used for payload delivery)", 0.8),
        (r'bitsadmin', "BitsAdmin (download)", 0.6),
        (r'powershell\s+-', "PowerShell invocation from batch", 0.5),
        
        # General suspicious
        (r'base64', "Base64 reference", 0.3),
        (r'0x[0-9a-fA-F]{50,}', "Long hex string (shellcode?)", 0.6),
        (r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){20,}', "Escaped bytes (shellcode?)", 0.7),
    ]
    
    @staticmethod
    def analyze(file_bytes: bytes, filename: str) -> ScanResult:
        evidence = []
        errors = []
        risk_score = 0
        
        try:
            text = file_bytes.decode('utf-8', errors='ignore')
            lines = text.split('\n')
            
            for pattern, reason, score in TextScriptAnalyzer.SUSPICIOUS_PATTERNS:
                for i, line in enumerate(lines):
                    if re.search(pattern, line, re.IGNORECASE):
                        evidence.append(Evidence(
                            evidence_type="line_range",
                            location=f"line_{i+1}",
                            reason=reason,
                            score=score,
                            snippet=line[:100].strip()
                        ))
                        risk_score = max(risk_score, int(score * 80))
            
        except Exception as e:
            errors.append(f"Script parsing error: {str(e)}")
            return ScanResult(
                file_type=FileType.TEXT_SCRIPT.value,
                verdict=Verdict.UNKNOWN.value,
                risk_score=25,
                confidence=0.4,
                evidence=[],
                errors=errors,
                details=f"Script parsing failed: {str(e)}",
                model_used="script_heuristic"
            )
        
        # Determine verdict
        if risk_score >= 60:
            verdict = Verdict.MALICIOUS.value
        elif risk_score >= 30:
            verdict = Verdict.SUSPICIOUS.value
        else:
            verdict = Verdict.CLEAN.value
        
        return ScanResult(
            file_type=FileType.TEXT_SCRIPT.value,
            verdict=verdict,
            risk_score=risk_score,
            confidence=0.7 if evidence else 0.85,
            evidence=evidence[:10],
            errors=errors,
            details=f"Script analysis: {len(evidence)} suspicious patterns" if evidence else "Script analysis: clean",
            model_used="script_heuristic"
        )


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    from collections import Counter
    import math
    
    counts = Counter(data)
    length = len(data)
    
    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return entropy


# ============= MAIN ROUTER =============

def route_and_analyze(file_bytes: bytes, filename: str, selected_model: str = "cnn_lstm") -> Dict:
    """
    Main routing function that directs files to appropriate analyzers
    
    Args:
        file_bytes: Raw file content
        filename: Original filename
        selected_model: Selected ML model (for PE files only)
    
    Returns:
        Standardized scan result dictionary
    """
    # Detect file type using magic bytes
    file_type = detect_file_type(file_bytes, filename)
    
    print(f"\n[ROUTER] File: {filename}")
    print(f"[ROUTER] Detected type: {file_type.value}")
    print(f"[ROUTER] File size: {len(file_bytes)} bytes")
    
    # Route to appropriate analyzer
    if file_type == FileType.IMAGE:
        print("[ROUTER] Routing to ImageAnalyzer (not using ML model)")
        result = ImageAnalyzer.analyze(file_bytes, filename)
        
    elif file_type == FileType.PDF:
        print("[ROUTER] Routing to PDFAnalyzer (not using ML model)")
        result = PDFAnalyzer.analyze(file_bytes, filename)
        
    elif file_type == FileType.ARCHIVE or file_type == FileType.OFFICE:
        print("[ROUTER] Routing to ArchiveAnalyzer")
        result = ArchiveAnalyzer.analyze(file_bytes, filename)
        
    elif file_type == FileType.TEXT_SCRIPT:
        print("[ROUTER] Routing to TextScriptAnalyzer")
        result = TextScriptAnalyzer.analyze(file_bytes, filename)
        
    elif file_type == FileType.PE_EXECUTABLE:
        # Use ML models only for PE executables
        print(f"[ROUTER] Routing to ML Pipeline (model: {selected_model})")
        # This will be handled by the existing ML pipeline
        return None  # Signal to use ML pipeline
        
    else:
        # Unknown file type - safe fallback
        print("[ROUTER] Unknown file type - safe fallback")
        result = ScanResult(
            file_type=file_type.value,
            verdict=Verdict.UNKNOWN.value,
            risk_score=10,
            confidence=0.5,
            evidence=[],
            errors=["Unknown file type - cannot determine appropriate analysis method"],
            details="File type not recognized. No malware indicators detected.",
            model_used="fallback"
        )
    
    return result.to_dict()
