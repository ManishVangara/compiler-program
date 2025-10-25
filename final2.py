import os
import uuid
import time
import subprocess
import re
import tempfile
import shutil
import sys
import json
from typing import List, Optional, Dict, Union
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# ============= ENVIRONMENT SETUP =============
load_dotenv()

# ============= FASTAPI INITIALIZATION =============
app = FastAPI(title="Code Execution Engine", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============= CONFIGURATION =============
SUPPORTED_LANGUAGES = ["python", "c", "cpp", "java", "javascript", "perl", "go"]
MAX_CODE_SIZE = 10000
MAX_EXECUTION_TIME = 5
MAX_MEMORY_MB = 150

# Security patterns per language
FORBIDDEN_PATTERNS = {
    "python": [
        r"import\s+(os|sys|subprocess|shutil|socket|urllib|requests)",
        r"__import__\s*\(",
        r"exec\s*\(",
        r"eval\s*\(",
        r"compile\s*\(",
        r"open\s*\(",
        r"file\s*\(",
    ],
    "javascript": [
        r"require\s*\(\s*['\"](?:fs|child_process|net|http|https)['\"]",
        r"eval\s*\(",
        r"Function\s*\(",
        r"process\.exit",
    ],
    "perl": [
        r"system\s*\(",
        r"exec\s+",
        r"`[^`]+`",
        r"open\s*\(",
        r"qx\s*[/\{]",
    ],
    "go": [
        r"os/exec",
        r"syscall",
        r"os\.Exec",
        r"exec\.Command",
    ],
    "c": [
        r"system\s*\(",
        r"exec[lv][ep]?\s*\(",
        r"popen\s*\(",
        r"fork\s*\(",
    ],
    "cpp": [
        r"system\s*\(",
        r"exec[lv][ep]?\s*\(",
        r"popen\s*\(",
        r"fork\s*\(",
    ],
    "java": [
        r"Runtime\.getRuntime\(\)",
        r"ProcessBuilder",
        r"System\.exit",
    ]
}

# ============= OPTIONAL MODULE IMPORTS =============
try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ============= REQUEST MODELS =============
class TestCase(BaseModel):
    input: Optional[Union[str, List[str]]] = ""
    expected_output: Optional[str] = ""
    
    def get_input_string(self) -> str:
        """Convert input to string format (handles both string and array)"""
        if isinstance(self.input, list):
            # Array format: ["5", "3"] -> "5\n3"
            return '\n'.join(str(item) for item in self.input)
        elif self.input:
            # String format: "5\n3" or "5 3"
            return str(self.input)
        else:
            return ""

class CodeRequest(BaseModel):
    language: str
    code: str
    test_cases: Optional[List[TestCase]] = []
    auto_generate: bool = False

# ============= AI PROVIDER FACTORY =============
class AIProviderFactory:
    """Factory for creating AI provider clients with flexible configuration"""
    
    @staticmethod
    def create_client(provider: Optional[str] = None):
        """Create AI client based on provider or environment variables"""
        provider = provider or os.getenv("AI_PROVIDER", "").lower()
        
        if provider == "openai" or os.getenv("OPENAI_API_KEY"):
            return AIProviderFactory._create_openai_client()
        elif provider == "anthropic" or os.getenv("ANTHROPIC_API_KEY"):
            return AIProviderFactory._create_anthropic_client()
        elif provider == "huggingface" or os.getenv("HF_TOKEN") or os.getenv("HF_API_KEY"):
            return AIProviderFactory._create_huggingface_client()
        
        return None
    
    @staticmethod
    def _create_openai_client():
        """Create OpenAI client"""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return None
        
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            print(f"OpenAI client initialized with model: {model}")
            return {"type": "openai", "client": client, "model": model}
        except ImportError:
            print("Warning: openai package not installed")
            return None
        except Exception as e:
            print(f"Warning: Failed to initialize OpenAI client: {e}")
            return None
    
    @staticmethod
    def _create_anthropic_client():
        """Create Anthropic client"""
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            return None
        
        try:
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
            print(f"Anthropic client initialized with model: {model}")
            return {"type": "anthropic", "client": client, "model": model}
        except ImportError:
            print("Warning: anthropic package not installed")
            return None
        except Exception as e:
            print(f"Warning: Failed to initialize Anthropic client: {e}")
            return None
    
    @staticmethod
    def _create_huggingface_client():
        """Create HuggingFace client"""
        api_key = os.getenv("HF_TOKEN") or os.getenv("HF_API_KEY")
        if not api_key:
            return None
        
        try:
            from huggingface_hub import InferenceClient
            client = InferenceClient(
                provider="fireworks-ai",
                api_key=api_key,
            )
            model = os.getenv("HF_MODEL", "openai/gpt-oss-20b")
            print(f"HuggingFace client initialized with model: {model}")
            return {"type": "huggingface", "client": client, "model": model}
        except ImportError:
            print("Warning: huggingface_hub package not installed")
            return None
        except Exception as e:
            print(f"Warning: Failed to initialize HuggingFace client: {e}")
            return None

# ============= SECURITY VALIDATION =============
def validate_code_security(code: str, language: str) -> tuple[bool, str]:
    """Validate code for security threats"""
    if len(code) > MAX_CODE_SIZE:
        return False, f"Code too large. Maximum {MAX_CODE_SIZE} characters allowed."
    
    if not code.strip():
        return False, "Code cannot be empty."
    
    if language in FORBIDDEN_PATTERNS:
        for pattern in FORBIDDEN_PATTERNS[language]:
            if re.search(pattern, code, re.IGNORECASE):
                return False, f"Security violation: Forbidden pattern detected for {language}."
    
    dangerous_patterns = [
        r"\.\.\/",
        r"\/etc\/",
        r"\/root\/",
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, code):
            return False, "Security violation: Dangerous file operation detected."
    
    return True, ""

# ============= CODE SANITIZATION =============
def sanitize_code(code: str) -> str:
    """Remove problematic Unicode characters"""
    return code.replace("\u00a0", " ").replace("\u202f", " ").replace("\u200b", "")

# ============= SYNTAX VALIDATION =============
def validate_python_syntax(code: str) -> bool:
    """Check if code is valid Python syntax using AST parser"""
    try:
        import ast
        ast.parse(code)
        return True
    except SyntaxError:
        return False
    except Exception:
        return True

def validate_javascript_syntax(code: str) -> bool:
    """Check if code is valid JavaScript syntax using Node.js"""
    try:
        result = subprocess.run(
            ['node', '--check', '-'],
            input=code,
            capture_output=True,
            text=True,
            timeout=2
        )
        return result.returncode == 0
    except Exception:
        return True

# ============= LANGUAGE DETECTION PATTERNS =============
WEIGHTED_LANGUAGE_PATTERNS = {
    "python": [
        (r"^\s*def\s+\w+\s*\(", 5),         # Function definition (strong)
        (r"^\s*class\s+\w+\s*:", 5),        # Class definition (strong)
        (r"^\s*import\s+\w+", 4),           # Import statement (strong)
        (r"^\s*from\s+\w+\s+import", 4),    # From import (strong)
        (r":\s*$", 2),                      # Colon at line end (weak)
        (r"\bprint\s*\(", 2),               # Print function (weak)
        (r"\binput\s*\(", 3),               # Input function (medium)
        (r"if\s+__name__\s*==\s*['\"]__main__['\"]", 5),  # Main guard (strong)
    ],
    "java": [
        (r"\bpublic\s+class\s+\w+", 5),     # Public class (strong)
        (r"\bpublic\s+static\s+void\s+main", 5),  # Main method (strong)
        (r"System\.out\.print", 4),         # Print statement (strong)
        (r"System\.in", 3),                 # Input (medium)
        (r"\bprivate\s+\w+\s+\w+", 3),      # Private field (medium)
        (r"new\s+\w+\s*\(", 2),             # Object creation (weak)
    ],
    "javascript": [
        (r"\bconsole\.(log|error|warn)", 5), # Console methods (strong)
        (r"\bconst\s+\w+\s*=", 3),          # Const declaration (medium)
        (r"\blet\s+\w+\s*=", 3),            # Let declaration (medium)
        (r"=>\s*{", 4),                     # Arrow function (strong)
        (r"\bfunction\s+\w+\s*\(", 3),      # Function declaration (medium)
        (r"\brequire\s*\(", 4),             # Require (strong)
        (r"\bvar\s+\w+\s*=", 2),            # Var declaration (weak)
    ],
    "go": [
        (r"^\s*package\s+main", 5),         # Package main (strong)
        (r"\bfunc\s+main\s*\(\s*\)", 5),    # Main function (strong)
        (r"\bfmt\.Print", 4),               # Print function (strong)
        (r":=", 3),                         # Short variable declaration (medium)
        (r"\bfunc\s+\w+\s*\(", 3),          # Function declaration (medium)
    ],
    "c": [
        (r"#include\s*<stdio\.h>", 5),      # Standard IO header (strong)
        (r"\bint\s+main\s*\(", 5),          # Main function (strong)
        (r"\bprintf\s*\(", 4),              # Printf (strong)
        (r"\bscanf\s*\(", 4),               # Scanf (strong)
        (r"#include\s*<stdlib\.h>", 3),     # Stdlib header (medium)
    ],
    "cpp": [
        (r"#include\s*<iostream>", 5),      # Iostream header (strong)
        (r"\bstd::", 4),                    # Std namespace (strong)
        (r"\bcout\s*<<", 4),                # Cout (strong)
        (r"\bcin\s*>>", 4),                 # Cin (strong)
        (r"\busing\s+namespace\s+std", 3),  # Using namespace (medium)
    ],
    "perl": [
        (r"^\s*use\s+strict", 4),           # Use strict (strong)
        (r"^\s*use\s+warnings", 4),         # Use warnings (strong)
        (r"\bprint\s*[\(\s]", 3),           # Print with/without parens (medium)
        (r"\$\w+", 2),                      # Scalar variable (weak)
        (r"<STDIN>", 4),                    # STDIN (strong)
    ],
}

NEGATIVE_PATTERNS = {
    "python": [
        (r"\bpublic\s+class\b", "Java"),
        (r"\bpublic\s+static\s+void\s+main", "Java"),
        (r"\bconsole\.(log|error|warn)", "JavaScript"),
        (r"#include\s*<", "C/C++"),
        (r"\bpackage\s+main\b", "Go"),
        (r"\bfunc\s+main\s*\(", "Go"),
        (r"\bSystem\.out\.print", "Java"),
    ],
    "java": [
        (r"^\s*def\s+\w+\s*\(", "Python"),
        (r"^\s*import\s+\w+$", "Python"),
        (r"\bconsole\.(log|error|warn)", "JavaScript"),
        (r"#include\s*<", "C/C++"),
        (r"\bpackage\s+main\b", "Go"),
        (r"(?<!\.)(?<!::)\bprint\s*\(", "Python"),  # Standalone print(), not method call
    ],
    "javascript": [
        (r"^\s*def\s+\w+\s*\(", "Python"),
        (r"\bpublic\s+class\b", "Java"),
        (r"#include\s*<", "C/C++"),
        (r"\bpackage\s+main\b", "Go"),
        (r"\bfunc\s+main\s*\(", "Go"),
        (r"\bSystem\.out\.print", "Java"),
    ],
    "go": [
        (r"^\s*def\s+\w+\s*\(", "Python"),
        (r"\bpublic\s+class\b", "Java"),
        (r"\bconsole\.(log|error|warn)", "JavaScript"),
        (r"#include\s*<iostream>", "C++"),
    ],
    "c": [
        (r"^\s*def\s+\w+\s*\(", "Python"),
        (r"\bpublic\s+class\b", "Java"),
        (r"\bconsole\.(log|error|warn)", "JavaScript"),
        (r"#include\s*<iostream>", "C++"),
        (r"\bstd::", "C++"),
        (r"\bcout\s*<<", "C++"),
    ],
    "cpp": [
        (r"^\s*def\s+\w+\s*\(", "Python"),
        (r"\bpublic\s+class\b", "Java"),
        (r"\bconsole\.(log|error|warn)", "JavaScript"),
        (r"\bpackage\s+main\b", "Go"),
    ],
    "perl": [
        (r"^\s*def\s+\w+\s*\(", "Python"),
        (r"\bpublic\s+class\b", "Java"),
        (r"\bconsole\.(log|error|warn)", "JavaScript"),
        (r"#include\s*<", "C/C++"),
    ],
}

# ============= LANGUAGE DETECTION FUNCTIONS =============
def calculate_language_score(code: str, language: str) -> int:
    """Calculate weighted score for a language based on patterns"""
    if language not in WEIGHTED_LANGUAGE_PATTERNS:
        return 0
    
    score = 0
    patterns = WEIGHTED_LANGUAGE_PATTERNS[language]
    
    for pattern, weight in patterns:
        if re.search(pattern, code, re.MULTILINE):
            score += weight
    
    return score

def guess_language_from_code(code: str) -> Optional[str]:
    """Guess the most likely language based on weighted patterns"""
    scores = {}
    
    for lang in WEIGHTED_LANGUAGE_PATTERNS.keys():
        scores[lang] = calculate_language_score(code, lang)
    
    if not scores:
        return None
    
    max_score = max(scores.values())
    if max_score >= 5:
        return max(scores, key=scores.get)
    
    return None

def detect_language_mismatch(code: str, declared_lang: str) -> tuple[bool, str]:
    """
    Enhanced multi-stage language mismatch detection with:
    1. Negative pattern checking (what shouldn't be there)
    2. Weighted pattern matching
    3. Syntax validation (for Python/JavaScript)
    """
    
    # Stage 1: Check for negative patterns (patterns from other languages)
    if declared_lang in NEGATIVE_PATTERNS:
        for pattern, other_lang in NEGATIVE_PATTERNS[declared_lang]:
            if re.search(pattern, code, re.MULTILINE):
                return True, f"Code contains {other_lang} syntax. Please select '{other_lang.lower()}' as the language"
    
    # Stage 2: Weighted pattern matching
    declared_score = calculate_language_score(code, declared_lang)
    guessed_lang = guess_language_from_code(code)
    
    if guessed_lang and guessed_lang != declared_lang:
        guessed_score = calculate_language_score(code, guessed_lang)
        if guessed_score > declared_score + 3:
            return True, f"Code appears to be {guessed_lang.title()} (confidence: high). Please select '{guessed_lang}' as the language."
    
    # Stage 3: Syntax validation for specific languages
    if declared_lang == "python":
        if not validate_python_syntax(code):
            if guessed_lang:
                return True, f"Invalid Python syntax. Code appears to be {guessed_lang.title()}. Please select the correct language."
            return True, "Invalid Python syntax. Please check your code or select the correct language."
    
    if declared_lang == "javascript":
        if not validate_javascript_syntax(code):
            if guessed_lang:
                return True, f"Invalid JavaScript syntax. Code appears to be {guessed_lang.title()}. Please select the correct language."
    
    # Stage 4: Low confidence check
    if declared_score == 0 and guessed_lang and guessed_lang != declared_lang:
        return True, f"Code doesn't appear to be {declared_lang.title()}. Did you mean '{guessed_lang}'?"
    
    return False, ""

# ============= UTILITY FUNCTIONS =============
def extract_java_class_name(code: str) -> str:
    """Extract Java class name, sanitized"""
    match = re.search(r"(?:public\s+)?class\s+(\w+)", code)
    if match:
        name = match.group(1)
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            return name
    return "Main"

def set_resource_limits():
    """Set resource limits for subprocess (Unix only)"""
    if not HAS_RESOURCE or os.name == "nt":
        return
    
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_EXECUTION_TIME + 5, MAX_EXECUTION_TIME + 5))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50*1024*1024, 50*1024*1024))
    except Exception:
        pass

def detect_input_requirement(code: str, language: str) -> bool:
    """Detect if code requires input"""
    input_patterns = {
        "python": r"\b(input|raw_input)\s*\(",
        "c": r"\b(scanf|gets|getchar|fgets)\s*\(",
        "cpp": r"\b(cin|scanf|gets|getline)\b",
        "java": r"\b(Scanner|BufferedReader|System\.in)\b",
        "javascript": r"\b(readline|prompt|process\.stdin)\b",
        "perl": r"<STDIN>|readline|<>",
        "go": r"\b(fmt\.Scan|bufio\.NewReader|os\.Stdin)\b"
    }
    
    pattern = input_patterns.get(language, r"\b(input|scanf|cin|Scanner)\b")
    has_input = bool(re.search(pattern, code))
    print(f"[DEBUG] Language: {language}, Has input: {has_input}")
    return has_input

# ============= EXECUTION FUNCTIONS =============
def run_with_timeout(cmd: List[str], input_data: str = "", timeout: int = MAX_EXECUTION_TIME, cwd: str = None) -> dict:
    """Execute command with timeout and resource monitoring"""
    try:
        preexec_fn = set_resource_limits if HAS_RESOURCE and os.name != "nt" else None
        
        if input_data:
            lines = input_data.strip().split('\n')
            input_data = '\n'.join(lines) + '\n'
        
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            preexec_fn=preexec_fn
        )
        
        max_memory_mb = 0
        start_time = time.time()
        
        if HAS_PSUTIL:
            import threading
            memory_samples = []
            stop_monitoring = threading.Event()
            
            def monitor_memory():
                try:
                    process = psutil.Process(proc.pid)
                    while not stop_monitoring.is_set():
                        try:
                            mem_info = process.memory_info()
                            current_mem = mem_info.rss
                            
                            for child in process.children(recursive=True):
                                try:
                                    child_mem = child.memory_info()
                                    current_mem += child_mem.rss
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            
                            memory_samples.append(current_mem)
                            time.sleep(0.01)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            break
                except Exception:
                    pass
            
            monitor_thread = threading.Thread(target=monitor_memory, daemon=True)
            monitor_thread.start()
        
        try:
            stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
            execution_time = time.time() - start_time
            
            if HAS_PSUTIL:
                stop_monitoring.set()
                monitor_thread.join(timeout=0.5)
                
                if memory_samples:
                    max_memory_mb = max(memory_samples) / (1024 * 1024)
                else:
                    try:
                        process = psutil.Process(proc.pid)
                        mem_info = process.memory_info()
                        max_memory_mb = mem_info.rss / (1024 * 1024)
                    except:
                        max_memory_mb = 0
            
            return {
                "returncode": proc.returncode,
                "stdout": stdout or "",
                "stderr": stderr or "",
                "time_sec": round(execution_time, 3),
                "memory_mb": round(max_memory_mb, 2)
            }
        
        except subprocess.TimeoutExpired:
            if HAS_PSUTIL:
                stop_monitoring.set()
                if memory_samples:
                    max_memory_mb = max(memory_samples) / (1024 * 1024)
            
            proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=1)
            except:
                stdout, stderr = "", ""
            
            return {
                "returncode": -1,
                "stdout": stdout or "",
                "stderr": f"Execution timeout after {timeout} seconds",
                "time_sec": timeout,
                "memory_mb": round(max_memory_mb, 2)
            }
    
    except Exception as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"Execution error: {str(e)}",
            "time_sec": 0,
            "memory_mb": 0
        }

def get_execute_command(lang: str, src_path: str, exe_path: str, temp_dir: str, class_name: Optional[str] = None) -> List[str]:
    """Get command to execute code based on language"""
    if lang == "java":
        if not class_name:
            raise ValueError("Java execution requires class_name")
        return ["java", "-cp", temp_dir, class_name]
    
    commands = {
        "python": [sys.executable, "-u", src_path],
        "javascript": ["node", src_path],
        "perl": ["perl", src_path],
        "go": [exe_path],
        "c": [exe_path],
        "cpp": [exe_path],
    }
    cmd = commands.get(lang)
    if cmd is None:
        raise ValueError(f"Unsupported language: {lang}")
    return cmd

def clean_output(text: str) -> str:
    """Clean output by removing input prompts and warnings"""
    text = re.sub(r"Enter\s+[^:]*:\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"Warning:\s*Could not set resource limits[^\n]*\n?", "", text, flags=re.IGNORECASE)
    return text.strip()

def run_once(cmd: List[str], temp_dir: str, language: str) -> dict:
    """Execute code once without test cases"""
    result = run_with_timeout(cmd, "", MAX_EXECUTION_TIME, temp_dir)
    
    if result["returncode"] == 0:
        status = "success"
    elif "timeout" in result["stderr"].lower():
        status = "timeout"
    else:
        status = "runtime_error"
    
    return {
        "stdout": clean_output(result["stdout"]),
        "stderr": result["stderr"],
        "status": status,
        "time": f"{result['time_sec']}s",
        "memory": f"{result['memory_mb']}MB",
        "language": language
    }

# ============= TEST CASE GENERATION =============
def generate_test_cases_with_ai(code: str, language: str, provider_info: Dict) -> List[TestCase]:
    """AI-powered test case generator with multi-provider support and enhanced validation"""
    if not provider_info:
        return []
    
    provider_type = provider_info["type"]
    client = provider_info["client"]
    model = provider_info["model"]
    
    print(f"Generating test cases using {provider_type} with model {model}...")
    
    # IMPROVED SYSTEM PROMPT - More explicit about expected_output requirement
    system_prompt = """You are a test case generator. Generate 2-3 test cases for code.
Return ONLY a valid JSON array, no markdown, no explanation.
Format: [{"input":"value","expected_output":"value"}] or 
Format: [{"input":["value1","value2"],"expected_output":"value"}]

CRITICAL REQUIREMENTS:
1. Every test case MUST have both 'input' AND 'expected_output'
2. The expected_output must be the EXACT output the code will produce
3. Calculate the expected output by mentally executing the code
4. For code without input, use empty string "" for input but ALWAYS provide expected_output
5. Expected output must be a string of what gets printed/returned

Example: For code that prints squares 1 to n:
- Input: "3" → Expected output: "1\\n4\\n9"
- Input: "2" → Expected output: "1\\n4"

If you cannot determine the expected output, do not generate that test case."""
    
    # IMPROVED USER PROMPT - More explicit instructions
    user_prompt = f"""Generate test cases for this {language.upper()} code:
```{language}
{code}
```

IMPORTANT RULES:
1. Return ONLY a JSON array - no markdown, no explanations, no code blocks
2. Use simple, realistic input values
3. For multiple inputs: use array format ["value1", "value2"] or newline-separated "value1\\nvalue2"
4. CRITICAL: Calculate and include the EXACT expected_output for each test case
5. The expected_output should be exactly what the code prints to stdout
6. If the code has no input, use empty string for input
7. Include 2-3 test cases maximum

Format: [
  {{"input": "test_input", "expected_output": "calculated_output"}},
  {{"input": ["val1", "val2"], "expected_output": "calculated_output"}}
]

JSON Array:"""
    
    try:
        # Call AI provider
        if provider_type == "openai":
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,  # Lower temperature for more consistent outputs
                max_tokens=800,   # Increased token limit
            )
            content = completion.choices[0].message.content.strip()
        
        elif provider_type == "anthropic":
            message = client.messages.create(
                model=model,
                max_tokens=800,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
            )
            content = message.content[0].text.strip()
        
        elif provider_type == "huggingface":
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=800,
            )
            content = completion.choices[0].message.content.strip()
        
        else:
            return []
        
        # DEBUG: Show raw response
        print(f"[DEBUG] AI response length: {len(content)} chars")
        print(f"[DEBUG] Response preview: {content[:150]}...")
        
        # Clean up response - remove markdown if present
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        
        # Extract JSON array
        json_match = re.search(r'\[[\s\S]*\]', content)
        if json_match:
            content = json_match.group(0)
        else:
            print("[ERROR] No JSON array found in AI response")
            return []
        
        # Parse JSON
        test_data = json.loads(content)
        
        # DEBUG: Show parsed data
        print(f"[DEBUG] Parsed {len(test_data)} test cases from AI")
        
        if not isinstance(test_data, list):
            print("[ERROR] AI response is not a JSON array")
            return []
        
        # IMPROVED VALIDATION: Ensure all test cases have expected_output
        test_cases = []
        for idx, tc in enumerate(test_data[:3], 1):
            if not isinstance(tc, dict):
                print(f"[WARNING] Test case {idx} is not a dict, skipping")
                continue
            
            # Extract fields
            input_data = tc.get("input", "")
            expected_output = tc.get("expected_output", "")
            
            # CRITICAL VALIDATION: Check if expected_output exists and is not empty
            if expected_output is None or str(expected_output).strip() == "":
                print(f"[WARNING] Test case {idx} missing expected_output: {tc}")
                print(f"[WARNING] Skipping test case without expected output")
                continue
            
            # Convert expected_output to string
            expected_output_str = str(expected_output).strip()
            
            # Create test case
            test_cases.append(
                TestCase(
                    input=input_data,
                    expected_output=expected_output_str
                )
            )
            print(f"[DEBUG] Test case {idx}: input={input_data}, expected={expected_output_str[:50]}...")
        
        if not test_cases:
            print("[ERROR] No valid test cases generated (all missing expected_output)")
            return []
        
        print(f"Successfully generated {len(test_cases)} valid test cases")
        return test_cases
    
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON parsing failed: {e}")
        print(f"[ERROR] Content: {content[:200]}...")
        return []
    except Exception as e:
        print(f"[ERROR] Test generation failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return []

# ============= COMPILATION HANDLERS =============
def compile_c_cpp(lang: str, src_path: str, exe_path: str, temp_dir: str) -> dict:
    """Compile C/C++ code"""
    compiler = "gcc" if lang == "c" else "g++"
    compiler_path = shutil.which(compiler)
    
    if not compiler_path:
        return {
            "success": False,
            "error": f"{lang.upper()} compiler not found. Please install {compiler}."
        }
    
    result = run_with_timeout([compiler_path, src_path, "-o", exe_path], timeout=10, cwd=temp_dir)
    
    if result["returncode"] != 0:
        return {
            "success": False,
            "error": result["stderr"],
            "time": result["time_sec"],
            "memory": result["memory_mb"]
        }
    
    return {"success": True}

def compile_java(src_path: str, temp_dir: str) -> dict:
    """Compile Java code"""
    javac = shutil.which("javac")
    
    if not javac:
        return {
            "success": False,
            "error": "Java compiler (javac) not found. Please install JDK."
        }
    
    result = run_with_timeout(["javac", src_path], timeout=10, cwd=temp_dir)
    
    if result["returncode"] != 0:
        return {
            "success": False,
            "error": result["stderr"],
            "time": result["time_sec"],
            "memory": result["memory_mb"]
        }
    
    return {"success": True}

def compile_go(src_path: str, exe_path: str, temp_dir: str) -> dict:
    """Compile Go code"""
    go_compiler = shutil.which("go")
    
    if not go_compiler:
        return {
            "success": False,
            "error": "Go compiler not found. Please install Go."
        }
    
    result = run_with_timeout(["go", "build", "-o", exe_path, src_path], timeout=10, cwd=temp_dir)
    
    if result["returncode"] != 0:
        return {
            "success": False,
            "error": result["stderr"],
            "time": result["time_sec"],
            "memory": result["memory_mb"]
        }
    
    return {"success": True}

def check_interpreter(lang: str) -> dict:
    """Check if interpreter is available"""
    interpreters = {
        "javascript": ("node", "Node.js"),
        "perl": ("perl", "Perl"),
        "python": (sys.executable, "Python")
    }
    
    if lang in interpreters:
        cmd, name = interpreters[lang]
        if not shutil.which(cmd):
            return {
                "success": False,
                "error": f"{name} interpreter not found. Please install {name}."
            }
    
    return {"success": True}

# ============= MAIN ENDPOINT =============
@app.post("/run")
def run_code(req: CodeRequest):
    """Main endpoint to execute code"""
    try:
        # Validate language
        lang = req.language.lower()
        if lang not in SUPPORTED_LANGUAGES:
            return {
                "stdout": "",
                "stderr": f"Unsupported language: {lang}. Supported: {', '.join(SUPPORTED_LANGUAGES)}",
                "status": "error",
                "time": "0s",
                "memory": "0MB",
                "language": lang
            }
        
        # Sanitize code
        cleaned_code = sanitize_code(req.code)
        
        # Security validation
        is_safe, security_error = validate_code_security(cleaned_code, lang)
        if not is_safe:
            return {
                "stdout": "",
                "stderr": security_error,
                "status": "error",
                "time": "0s",
                "memory": "0MB",
                "language": lang
            }
        
        # Language mismatch detection
        is_mismatch, mismatch_msg = detect_language_mismatch(cleaned_code, lang)
        if is_mismatch:
            return {
                "stdout": "",
                "stderr": f"Language mismatch: {mismatch_msg}",
                "status": "error",
                "time": "0s",
                "memory": "0MB",
                "language": lang
            }
        
        # Check if code needs input
        needs_input = detect_input_requirement(cleaned_code, lang)
        
        # Process with temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            fid = uuid.uuid4().hex
            
            # Determine filename
            if lang == "java":
                class_name = extract_java_class_name(cleaned_code)
                filename = f"{class_name}.java"
            else:
                extensions = {
                    "python": "py", "c": "c", "cpp": "cpp",
                    "javascript": "js", "perl": "pl", "go": "go"
                }
                filename = f"{fid}.{extensions[lang]}"
            
            src_path = os.path.join(temp_dir, filename)
            exe_path = os.path.join(temp_dir, fid + (".exe" if os.name == "nt" else ""))
            
            # Write code to file
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(cleaned_code)
            
            # Compilation phase for compiled languages
            class_name = None
            if lang in ["c", "cpp"]:
                compile_result = compile_c_cpp(lang, src_path, exe_path, temp_dir)
                if not compile_result["success"]:
                    return {
                        "stdout": "",
                        "stderr": compile_result["error"],
                        "status": "compilation_failed",
                        "time": f"{compile_result.get('time', 0)}s",
                        "memory": f"{compile_result.get('memory', 0)}MB",
                        "language": lang
                    }
            
            elif lang == "java":
                class_name = extract_java_class_name(cleaned_code)
                compile_result = compile_java(src_path, temp_dir)
                if not compile_result["success"]:
                    return {
                        "stdout": "",
                        "stderr": compile_result["error"],
                        "status": "compilation_failed",
                        "time": f"{compile_result.get('time', 0)}s",
                        "memory": f"{compile_result.get('memory', 0)}MB",
                        "language": lang
                    }
            
            elif lang == "go":
                compile_result = compile_go(src_path, exe_path, temp_dir)
                if not compile_result["success"]:
                    return {
                        "stdout": "",
                        "stderr": compile_result["error"],
                        "status": "compilation_failed",
                        "time": f"{compile_result.get('time', 0)}s",
                        "memory": f"{compile_result.get('memory', 0)}MB",
                        "language": lang
                    }
            
            else:
                # Check interpreter availability
                interp_check = check_interpreter(lang)
                if not interp_check["success"]:
                    return {
                        "stdout": "",
                        "stderr": interp_check["error"],
                        "status": "error",
                        "time": "0s",
                        "memory": "0MB",
                        "language": lang
                    }
            
            # Execution phase
            cmd = get_execute_command(lang, src_path, exe_path, temp_dir, class_name)
            
            # Auto-generate test cases if requested
            if req.auto_generate and not req.test_cases:
                if needs_input:
                    ai_client = AIProviderFactory.create_client()
                    if ai_client:
                        generated_cases = generate_test_cases_with_ai(cleaned_code, lang, ai_client)
                        if generated_cases:
                            req.test_cases = generated_cases
                            print(f"Auto-generated {len(generated_cases)} test cases using {ai_client['type']}")
                        else:
                            print("Failed to generate test cases, running without tests")
                    else:
                        return {
                            "stdout": "",
                            "stderr": "Auto-generate requires AI provider. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or HF_TOKEN.",
                            "status": "error",
                            "time": "0s",
                            "memory": "0MB",
                            "language": lang
                        }
                else:
                    print("Code doesn't require input, skipping test case generation")
            
            # If no test cases provided and no input needed, run once
            if not req.test_cases and not needs_input:
                return run_once(cmd, temp_dir, lang)
            
            # Execute with test cases
            test_cases = req.test_cases if req.test_cases else [TestCase(input="", expected_output="")]
            
            results = []
            total_time = 0
            max_memory = 0
            passed_count = 0
            
            for idx, tc in enumerate(test_cases, 1):
                # Use the new get_input_string method for flexible input handling
                input_data = tc.get_input_string() if needs_input else ""
                expected = tc.expected_output or ""
                
                print(f"Test {idx}: Sending input: {repr(input_data)}")
                
                result = run_with_timeout(cmd, input_data, MAX_EXECUTION_TIME, temp_dir)
                
                actual = clean_output(result["stdout"])
                expected_clean = clean_output(expected)
                
                passed = actual == expected_clean if expected else None
                if passed:
                    passed_count += 1
                
                total_time += result["time_sec"]
                max_memory = max(max_memory, result["memory_mb"])
                
                results.append({
                    "test_case": idx,
                    "input": tc.input,  # Store original format
                    "expected_output": expected,
                    "actual_output": actual,
                    "passed": passed if expected else "N/A",
                    "time": f"{result['time_sec']}s",
                    "memory": f"{result['memory_mb']}MB",
                    "error": result["stderr"] if result["returncode"] != 0 else ""
                })
            
            return {
                "stdout": "",
                "stderr": "",
                "status": "success",
                "time": f"{round(total_time, 3)}s",
                "memory": f"{round(max_memory, 2)}MB",
                "language": lang,
                "test_results": results,
                "summary": {
                    "total": len(test_cases),
                    "passed": passed_count,
                    "failed": len(test_cases) - passed_count
                }
            }
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "stdout": "",
            "stderr": f"Internal error: {str(e)}",
            "status": "error",
            "time": "0s",
            "memory": "0MB",
            "language": req.language
        }

# ============= HEALTH CHECK ENDPOINTS =============
@app.get("/")
def health_check():
    """Health check endpoint"""
    return {
        "status": "online",
        "supported_languages": SUPPORTED_LANGUAGES,
        "version": "1.0.0",
        "ai_providers": ["openai", "anthropic", "huggingface"]
    }

@app.get("/languages")
def get_languages():
    """Get list of supported languages"""
    return {
        "languages": SUPPORTED_LANGUAGES
    }


@app.get("/ai-provider")
def get_ai_provider_info():
    """Get current AI provider configuration"""
    provider_info = AIProviderFactory.create_client()
    
    if provider_info:
        return {
            "status": "configured",
            "provider": provider_info["type"],
            "model": provider_info["model"],
            "test_generation_enabled": True
        }
    else:
        # Check which environment variables are missing
        available_providers = []
        if os.getenv("OPENAI_API_KEY"):
            available_providers.append("OpenAI (API key set but client failed to initialize)")
        if os.getenv("ANTHROPIC_API_KEY"):
            available_providers.append("Anthropic (API key set but client failed to initialize)")
        if os.getenv("HF_TOKEN") or os.getenv("HF_API_KEY"):
            available_providers.append("HuggingFace (Token set but client failed to initialize)")
            
        return {
            "status": "not_configured",
            "provider": None,
            "model": None,
            "test_generation_enabled": False,
            "message": "No AI provider configured. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or HF_TOKEN",
            "detected_keys": available_providers if available_providers else ["No API keys detected"]
        }

# ============= APPLICATION ENTRY POINT =============
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)