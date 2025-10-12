import os
import uuid
import time
import subprocess
import re
import json
import traceback
import shutil
import tempfile
import signal
import sys
import openai
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# Optional modules
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

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPPORTED_LANGUAGES = ["python", "c", "cpp", "java", "javascript", "perl", "go"]
MAX_CODE_SIZE = 10000
MAX_EXECUTION_TIME = 5
MAX_MEMORY_MB = 150

# Keep base forbidden keywords (Python-focused)
FORBIDDEN_KEYWORDS = [
    "import os", "import sys", "import subprocess", "import shutil",
    "system(", "exec(", "eval(", "open(", "file(", "__import__",
    "compile(", "execfile(", "raw_input("
]

class CodeRequest(BaseModel):
    language: str
    code: str
    auto_generate: bool = False
    manual_cases: Optional[List[str]] = []

def extract_java_class_name(code: str) -> str:
    match = re.search(r"(?:public\s+)?class\s+(\w+)", code)
    return match.group(1) if match else "Main"

def extract_go_package_name(code: str) -> str:
    """Extract package name from Go code, default to 'main'"""
    match = re.search(r"package\s+(\w+)", code)
    return match.group(1) if match else "main"

def validate_code_security(code: str, language: str = "python") -> tuple[bool, str]:
    """Validate code for security threats - basic checks only"""
    if len(code) > MAX_CODE_SIZE:
        return False, f"Code too large. Maximum {MAX_CODE_SIZE} characters allowed."
    
    code_lower = code.lower()
    
    # Check base forbidden keywords only
    for keyword in FORBIDDEN_KEYWORDS:
        if re.search(r"\b" + re.escape(keyword), code_lower):
            return False, f"Security violation: '{keyword}' is not allowed."
    
    # Keep suspicious patterns check
    suspicious_patterns = [
        r"__.*__", r"import\s+\*", r"exec\s*\(", r"eval\s*\(", r"__import__\s*\("
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, code_lower):
            return False, f"Security violation: Pattern '{pattern}' is not allowed."
    
    # Keep dangerous file operations check
    dangerous_file_ops = [
        r"open\s*\([^)]*['\"][^'\"]*\.(py|exe|bat|cmd|sh|ps1)",
        r"open\s*\([^)]*['\"][^'\"]*\.(txt|log|ini|cfg|conf)",
        r"open\s*\([^)]*['\"]/",
        r"open\s*\([^)]*['\"]\.\./"
    ]
    for pattern in dangerous_file_ops:
        if re.search(pattern, code_lower):
            return False, "Security violation: Dangerous file operation detected."
    
    return True, ""

def set_resource_limits():
    if not HAS_RESOURCE:
        return
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY_MB * 1024 * 1024, -1))
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_EXECUTION_TIME, MAX_EXECUTION_TIME))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024*1024, 1024*1024))
    except Exception:
        pass

def run_with_timeout(cmd, input_data="", timeout=MAX_EXECUTION_TIME, temp_dir=None):
    """Execute command with timeout and memory tracking - PHASE 2"""
    try:
        preexec_fn = set_resource_limits if HAS_RESOURCE and os.name != "nt" else None
        kwargs = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "cwd": temp_dir,
            "preexec_fn": preexec_fn
        }
        proc = subprocess.Popen(cmd, **kwargs)
        
        # Memory tracking
        max_memory_mb = 0
        start_time = time.time()
        
        try:
            # Monitor memory if psutil available
            if HAS_PSUTIL:
                process = psutil.Process(proc.pid)
                while proc.poll() is None:
                    try:
                        mem_info = process.memory_info()
                        current_mem_mb = mem_info.rss / (1024 * 1024)
                        max_memory_mb = max(max_memory_mb, current_mem_mb)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    # Check timeout
                    if time.time() - start_time > timeout:
                        raise subprocess.TimeoutExpired(cmd, timeout)
                    time.sleep(0.01)
            
            # Get output
            stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
            execution_time = time.time() - start_time
            
            return {
                "returncode": proc.returncode,
                "stdout": stdout or "",
                "stderr": stderr or "",
                "time_sec": round(execution_time, 3),
                "memory_mb": round(max_memory_mb, 2)
            }
            
        except subprocess.TimeoutExpired:
            # Kill process
            if HAS_PSUTIL:
                try:
                    parent = psutil.Process(proc.pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                    parent.kill()
                except:
                    pass
            else:
                if os.name != "nt":
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except:
                        proc.kill()
                else:
                    proc.kill()
            
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Execution timeout - Process killed after {} seconds".format(timeout),
                "time_sec": timeout,
                "memory_mb": round(max_memory_mb, 2)
            }
    except Exception as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "time_sec": 0,
            "memory_mb": 0
        }

def build_standard_response(result, language):
    """Build standardized response format - PHASE 2"""
    if result["returncode"] == 0:
        status = "success"
    elif result["returncode"] == -1:
        status = "timeout" if "timeout" in result["stderr"].lower() else "error"
    else:
        status = "runtime_error"
    
    return {
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "status": status,
        "time": f"{result['time_sec']}s",
        "memory": f"{result['memory_mb']}MB",
        "language": language
    }

@app.post("/run")
def run_code(req: CodeRequest):
    try:
        lang = req.language.lower()
        if lang not in SUPPORTED_LANGUAGES:
            raise HTTPException(status_code=400, detail="Unsupported language")
        
        is_safe, err = validate_code_security(req.code, lang)
        if not is_safe:
            raise HTTPException(status_code=400, detail=err)
        
        cleaned_code = sanitize_code(req.code)
        
        # Language mismatch detection
        language_signatures = {
            "python": ["def ", "import ", "print("],
            "cpp": ["#include", "std::", "cout"],
            "c": ["#include", "printf"],
            "java": ["public class", "public static void main"],
            "javascript": ["console.log", "function ", "const ", "let ", "var "],
            "perl": ["use ", "my $", "print "],
            "go": ["package ", "func ", "import "]
        }
        
        for detect_lang, signatures in language_signatures.items():
            if detect_lang != lang:
                if any(sig in cleaned_code for sig in signatures[:2]):
                    return {
                        "stdout": "",
                        "stderr": f"Code looks like {detect_lang.upper()} but {lang.upper()} was selected",
                        "status": "error",
                        "time": "0s",
                        "memory": "0MB",
                        "language": lang
                    }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            fid = uuid.uuid4().hex
            class_name = extract_java_class_name(cleaned_code) if lang == "java" else None
            
            filename = {
                "python": f"{fid}.py",
                "c": f"{fid}.c",
                "cpp": f"{fid}.cpp",
                "java": f"{class_name}.java",
                "javascript": f"{fid}.js",
                "perl": f"{fid}.pl",
                "go": f"{fid}.go"
            }[lang]
            
            src_path = os.path.join(temp_dir, filename)
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(cleaned_code)
            
            exe_path = os.path.join(temp_dir, fid + (".exe" if os.name == "nt" else ""))
            
            # Detect if code needs input
            input_patterns = {
                "python": r"\b(input|raw_input)\s*\(",
                "c": r"\b(scanf|gets|getchar|fgets)\s*\(",
                "cpp": r"\b(cin|scanf|gets|getline)\b",
                "java": r"\b(Scanner|BufferedReader|System\.in)\b",
                "javascript": r"\b(readline|prompt|process\.stdin)\b",
                "perl": r"\b(<STDIN>|<>|readline)\b",
                "go": r"\b(fmt\.Scan|bufio\.NewReader|os\.Stdin)\b"
            }
            pattern = input_patterns.get(lang, r"\b(input|scanf|cin|Scanner)\b")
            needs_input = bool(re.search(pattern, cleaned_code))
            
            nondet = any(tok in cleaned_code for tok in ("random", "time(", "datetime", "now()", "currentTimeMillis", "Math.random"))
            
            # Test cases
            test_cases = []
            if req.auto_generate:
                if nondet:
                    return {
                        "stdout": "",
                        "stderr": "Code contains randomness, skipping test validation.",
                        "status": "warning",
                        "time": "0s",
                        "memory": "0MB",
                        "language": lang,
                        "raw_output": run_once(lang, src_path, exe_path, temp_dir, class_name)
                    }
                test_cases = generate_test_cases(cleaned_code, lang)
            elif req.manual_cases:
                for i in range(0, len(req.manual_cases or []), 2):
                    inp = req.manual_cases[i]
                    exp = req.manual_cases[i+1] if i+1 < len(req.manual_cases) else ""
                    test_cases.append({"input": inp, "expected_output": exp})
            
            # Compile if needed
            if lang in ("c", "cpp"):
                compiler = shutil.which("gcc") if lang == "c" else shutil.which("g++")
                if not compiler:
                    return {
                        "stdout": "",
                        "stderr": f"{lang.upper()} compiler not found",
                        "status": "error",
                        "time": "0s",
                        "memory": "0MB",
                        "language": lang
                    }
                result = run_with_timeout([compiler, src_path, "-o", exe_path], timeout=10, temp_dir=temp_dir)
                if result["returncode"] != 0:
                    return {
                        "stdout": "",
                        "stderr": result["stderr"],
                        "status": "compilation_failed",
                        "time": f"{result['time_sec']}s",
                        "memory": f"{result['memory_mb']}MB",
                        "language": lang
                    }
            elif lang == "java":
                javac = shutil.which("javac")
                if not javac:
                    return {
                        "stdout": "",
                        "stderr": "Java compiler (javac) not found",
                        "status": "error",
                        "time": "0s",
                        "memory": "0MB",
                        "language": lang
                    }
                result = run_with_timeout(["javac", src_path], timeout=10, temp_dir=temp_dir)
                if result["returncode"] != 0:
                    return {
                        "stdout": "",
                        "stderr": result["stderr"],
                        "status": "compilation_failed",
                        "time": f"{result['time_sec']}s",
                        "memory": f"{result['memory_mb']}MB",
                        "language": lang
                    }
            elif lang == "go":
                go_compiler = shutil.which("go")
                if not go_compiler:
                    return {
                        "stdout": "",
                        "stderr": "Go compiler not found",
                        "status": "error",
                        "time": "0s",
                        "memory": "0MB",
                        "language": lang
                    }
                result = run_with_timeout(["go", "build", "-o", exe_path, src_path], timeout=10, temp_dir=temp_dir)
                if result["returncode"] != 0:
                    return {
                        "stdout": "",
                        "stderr": result["stderr"],
                        "status": "compilation_failed",
                        "time": f"{result['time_sec']}s",
                        "memory": f"{result['memory_mb']}MB",
                        "language": lang
                    }
            elif lang == "javascript":
                if not shutil.which("node"):
                    return {
                        "stdout": "",
                        "stderr": "Node.js not installed",
                        "status": "error",
                        "time": "0s",
                        "memory": "0MB",
                        "language": lang
                    }
            elif lang == "perl":
                if not shutil.which("perl"):
                    return {
                        "stdout": "",
                        "stderr": "Perl interpreter not installed",
                        "status": "error",
                        "time": "0s",
                        "memory": "0MB",
                        "language": lang
                    }
            
            # Execute code
            if not test_cases and not needs_input:
                return run_once(lang, src_path, exe_path, temp_dir, class_name)
            
            if not test_cases:
                test_cases = [{"input": "", "expected_output": ""}]
            
            # Execute with test cases
            results, passed = [], 0
            for tc in test_cases:
                inp = tc["input"].strip() + "\n" if needs_input else ""
                exp = tc["expected_output"]
                cmd = get_command(lang, src_path, exe_path, temp_dir, class_name)
                result = run_with_timeout(cmd, inp, MAX_EXECUTION_TIME, temp_dir)
                actual = clean_output(result["stdout"])
                expected = clean_output(exp)
                ok = "N/A" if nondet else (actual == expected)
                if ok is True:
                    passed += 1
                results.append({
                    "input": tc["input"],
                    "expected_output": exp,
                    "actual_output": actual,
                    "passed": ok,
                    "time": f"{result['time_sec']}s",
                    "memory": f"{result['memory_mb']}MB"
                })
            
            total_time = sum(float(r['time'].rstrip('s')) for r in results)
            max_memory = max(float(r['memory'].rstrip('MB')) for r in results)
            
            return {
                "stdout": "",
                "stderr": "",
                "status": "success",
                "time": f"{round(total_time, 3)}s",
                "memory": f"{round(max_memory, 2)}MB",
                "language": lang,
                "test_results": results,
                "summary": {
                    "total": len(results) if not nondet else "N/A",
                    "passed": passed if not nondet else "N/A",
                    "failed": len(results) - passed if not nondet else "N/A"
                }
            }
    except HTTPException as he:
        return {
            "stdout": "",
            "stderr": str(he.detail),
            "status": "error",
            "time": "0s",
            "memory": "0MB",
            "language": req.language
        }
    except Exception as e:
        traceback.print_exc()
        return {
            "stdout": "",
            "stderr": f"Internal server error: {str(e)}",
            "status": "error",
            "time": "0s",
            "memory": "0MB",
            "language": req.language
        }

# --------- Utility Functions ---------
def sanitize_code(code: str) -> str:
    return code.replace("\u00a0", " ").replace("\u202f", " ").replace("\u200b", "")

def get_command(lang, src_path, exe_path, tmp_dir, class_name=None):
    """Generate the command to execute code based on language"""
    if lang == "python":
        return [sys.executable, "-u", "-E", "-S", src_path]
    elif lang == "javascript":
        return ["node", src_path]
    elif lang == "perl":
        return ["perl", src_path]
    elif lang == "go":
        return [exe_path]
    elif lang in ("c", "cpp"):
        return [exe_path]
    elif lang == "java":
        return ["java", "-cp", tmp_dir, class_name]
    else:
        raise ValueError(f"Unsupported language: {lang}")

def run_once(lang, src_path, exe_path, temp_dir, class_name=None):
    """Execute code once and return standardized result - PHASE 2"""
    cmd = get_command(lang, src_path, exe_path, temp_dir, class_name)
    result = run_with_timeout(cmd, timeout=MAX_EXECUTION_TIME, temp_dir=temp_dir)
    return build_standard_response(result, lang)

def clean_output(text: str) -> str:
    return re.sub(r"Enter\s+[^:]*:\s*", "", text, flags=re.I).strip()

def generate_test_cases(code: str, language: str) -> List[dict]:
    """
    AI-powered test case generator using OpenAI GPT-4
    Generates test cases based on code analysis
    """
    prompt = f"""
You are a test case generator. Given this {language.upper()} code, return exactly 2 test cases in JSON format:
[{{"input":"...","expected_output":"..."}},{{"input":"...","expected_output":"..."}}]
If the code has no input() or scanf() or similar input function, leave "input" empty.
Only return valid JSON array, nothing else.
Code:
{code}
"""
    try:
        resp = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            request_timeout=10
        )
        content = resp.choices[0].message.content.strip()
        
        # Try to extract JSON from response
        # Sometimes GPT returns markdown code blocks
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        
        return json.loads(content)
    except Exception as e:
        print(f"OpenAI test generation failed: {str(e)}")
        # Return default empty test case if OpenAI fails
        return [{"input": "", "expected_output": ""}]