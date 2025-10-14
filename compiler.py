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
    """Execute command with timeout - FIXED VERSION"""
    try:
        preexec_fn = set_resource_limits if HAS_RESOURCE and os.name != "nt" else None
        
        start_time = time.time()
        
        # CRITICAL FIX: Ensure input ends with newline if it has content
        # but don't double-add if it already ends with newline
        if input_data and not input_data.endswith('\n'):
            input_data = input_data + '\n'
        
        # Run process and wait for completion with input
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=temp_dir,
            preexec_fn=preexec_fn
        )
        
        execution_time = time.time() - start_time
        
        # Memory tracking for completed process is not reliable
        max_memory_mb = 0
        
        return {
            "returncode": result.returncode,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "time_sec": round(execution_time, 3),
            "memory_mb": round(max_memory_mb, 2)
        }
        
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -1,
            "stdout": e.stdout or "",
            "stderr": f"Execution timeout - Process killed after {timeout} seconds",
            "time_sec": timeout,
            "memory_mb": 0
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
    """Build standardized response format"""
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
                # CRITICAL FIX: Ensure input ends with newline for proper EOF handling
                inp = tc["input"] if needs_input else ""
                if inp and not inp.endswith('\n'):
                    inp = inp + '\n'
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
"""
Add this complete debug endpoint to your FastAPI app
Add it right after your existing @app.post("/run") endpoint
"""
### Debug Endpoint ###
@app.post("/debug-run")
def debug_run_code(req: CodeRequest):
    """Debug version with extensive logging - returns diagnostic info"""
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    debug_info = {
        "steps": [],
        "test_results": []
    }
    
    try:
        lang = req.language.lower()
        debug_info["steps"].append(f"Language: {lang}")
        
        # Sanitize code
        cleaned_code = req.code.replace("\u00a0", " ").replace("\u202f", " ").replace("\u200b", "")
        debug_info["steps"].append(f"Code length: {len(cleaned_code)} chars")
        debug_info["code_preview"] = cleaned_code[:200] + "..." if len(cleaned_code) > 200 else cleaned_code
        
        with tempfile.TemporaryDirectory() as temp_dir:
            fid = uuid.uuid4().hex
            filename = f"{fid}.py"
            src_path = os.path.join(temp_dir, filename)
            
            # Write code to file
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(cleaned_code)
            
            debug_info["steps"].append(f"Code written to: {src_path}")
            
            # Parse test cases
            test_cases = []
            for i in range(0, len(req.manual_cases or []), 2):
                inp = req.manual_cases[i]
                exp = req.manual_cases[i+1] if i+1 < len(req.manual_cases) else ""
                test_cases.append({"input": inp, "expected_output": exp})
            
            debug_info["steps"].append(f"Parsed {len(test_cases)} test cases")
            debug_info["test_cases"] = test_cases
            
            if not test_cases:
                return {
                    "error": "No test cases provided",
                    "debug_info": debug_info
                }
            
            # Test each case
            for idx, tc in enumerate(test_cases):
                test_debug = {
                    "test_number": idx + 1,
                    "input_raw": repr(tc["input"]),
                    "expected": tc["expected_output"],
                    "methods": []
                }
                
                inp = tc["input"]
                
                # Ensure ends with newline
                if inp and not inp.endswith('\n'):
                    inp = inp + '\n'
                
                test_debug["input_processed"] = repr(inp)
                test_debug["input_bytes"] = list(inp.encode('utf-8'))
                
                cmd = [sys.executable, "-u", src_path]
                test_debug["command"] = cmd
                
                # METHOD 1: subprocess.run
                method1 = {"name": "subprocess.run"}
                try:
                    start = time.time()
                    result = subprocess.run(
                        cmd,
                        input=inp,
                        capture_output=True,
                        text=True,
                        timeout=2,
                        cwd=temp_dir
                    )
                    elapsed = time.time() - start
                    
                    method1["success"] = True
                    method1["time"] = f"{elapsed:.3f}s"
                    method1["returncode"] = result.returncode
                    method1["stdout"] = result.stdout
                    method1["stderr"] = result.stderr
                    method1["matched"] = result.stdout.strip() == tc["expected_output"].strip()
                    
                except subprocess.TimeoutExpired as e:
                    method1["success"] = False
                    method1["error"] = "TIMEOUT after 2s"
                    method1["partial_stdout"] = e.stdout
                    method1["partial_stderr"] = e.stderr
                except Exception as e:
                    method1["success"] = False
                    method1["error"] = str(e)
                
                test_debug["methods"].append(method1)
                
                # METHOD 2: Popen with stdin.write (only if method 1 failed)
                if not method1.get("success"):
                    method2 = {"name": "Popen_stdin_write"}
                    try:
                        start = time.time()
                        proc = subprocess.Popen(
                            cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            cwd=temp_dir
                        )
                        
                        proc.stdin.write(inp)
                        proc.stdin.flush()
                        proc.stdin.close()
                        
                        stdout, stderr = proc.communicate(timeout=2)
                        elapsed = time.time() - start
                        
                        method2["success"] = True
                        method2["time"] = f"{elapsed:.3f}s"
                        method2["returncode"] = proc.returncode
                        method2["stdout"] = stdout
                        method2["stderr"] = stderr
                        method2["matched"] = stdout.strip() == tc["expected_output"].strip()
                        
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        method2["success"] = False
                        method2["error"] = "TIMEOUT after 2s"
                    except Exception as e:
                        method2["success"] = False
                        method2["error"] = str(e)
                    
                    test_debug["methods"].append(method2)
                
                # METHOD 3: Write input to file and redirect stdin (only if both failed)
                if not any(m.get("success") for m in test_debug["methods"]):
                    method3 = {"name": "stdin_from_file"}
                    try:
                        input_file = os.path.join(temp_dir, f"input_{idx}.txt")
                        with open(input_file, "w") as f:
                            f.write(inp)
                        
                        start = time.time()
                        with open(input_file, "r") as f:
                            result = subprocess.run(
                                cmd,
                                stdin=f,
                                capture_output=True,
                                text=True,
                                timeout=2,
                                cwd=temp_dir
                            )
                        elapsed = time.time() - start
                        
                        method3["success"] = True
                        method3["time"] = f"{elapsed:.3f}s"
                        method3["returncode"] = result.returncode
                        method3["stdout"] = result.stdout
                        method3["stderr"] = result.stderr
                        method3["matched"] = result.stdout.strip() == tc["expected_output"].strip()
                        
                    except subprocess.TimeoutExpired:
                        method3["success"] = False
                        method3["error"] = "TIMEOUT after 2s"
                    except Exception as e:
                        method3["success"] = False
                        method3["error"] = str(e)
                    
                    test_debug["methods"].append(method3)
                
                debug_info["test_results"].append(test_debug)
            
            # Summary
            working_method = None
            for test in debug_info["test_results"]:
                for method in test["methods"]:
                    if method.get("success") and method.get("matched"):
                        working_method = method["name"]
                        break
                if working_method:
                    break
            
            debug_info["summary"] = {
                "total_tests": len(test_cases),
                "working_method": working_method if working_method else "NONE - All methods failed",
                "diagnosis": "Check the detailed test_results for each method's output"
            }
            
            return debug_info
        
    except Exception as e:
        import traceback
        debug_info["error"] = str(e)
        debug_info["traceback"] = traceback.format_exc()
        return debug_info


# Also add this simple test endpoint
@app.post("/simple-test")
def simple_test():
    """Most basic test - no input needed"""
    try:
        code = "print('Hello from Python')"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = os.path.join(temp_dir, "test.py")
            with open(test_file, "w") as f:
                f.write(code)
            
            result = subprocess.run(
                [sys.executable, "-u", test_file],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "message": "If this works, Python execution is fine. The issue is with input handling."
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
# --------- Utility Functions ---------

def sanitize_code(code: str) -> str:
    return code.replace("\u00a0", " ").replace("\u202f", " ").replace("\u200b", "")

def get_command(lang, src_path, exe_path, tmp_dir, class_name=None):
    """Generate the command to execute code based on language"""
    if lang == "python":
        return [sys.executable, "-u", src_path]
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
    """Execute code once and return standardized result"""
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