import os
import uuid
import time
import subprocess
import re
import tempfile
import shutil
import sys
import json
from typing import List, Optional, Dict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Code Execution Engine", version="1.0.0")

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


class TestCase(BaseModel):
    input: str
    expected_output: Optional[str] = ""


class CodeRequest(BaseModel):
    language: str
    code: str
    test_cases: Optional[List[TestCase]] = []
    auto_generate: bool = False


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


def sanitize_code(code: str) -> str:
    """Remove problematic Unicode characters"""
    return code.replace("\u00a0", " ").replace("\u202f", " ").replace("\u200b", "")


def detect_language_mismatch(code: str, declared_lang: str) -> tuple[bool, str]:
    """Detect if code language doesn't match declared language"""
    code_lower = code.lower()
    
    python_indicators = ["def ", "import ", "print(", "input("]
    python_score = sum(1 for indicator in python_indicators if indicator in code_lower)
    
    java_indicators = ["public class", "public static void main", "System.out.println"]
    java_score = sum(1 for indicator in java_indicators if indicator in code_lower)
    
    js_indicators = ["console.log", "const ", "let ", "=>", "function"]
    js_score = sum(1 for indicator in js_indicators if indicator in code_lower)
    
    go_indicators = ["package main", "func main()", "fmt.Println"]
    go_score = sum(1 for indicator in go_indicators if indicator in code_lower)
    
    cpp_indicators = ["std::", "cout <<", "cin >>", "#include <iostream>"]
    cpp_score = sum(1 for indicator in cpp_indicators if indicator in code_lower)
    
    if declared_lang == "python" and python_score == 0 and (java_score >= 2 or js_score >= 2 or go_score >= 2):
        return True, "Code doesn't appear to be Python"
    
    if declared_lang == "java" and java_score == 0 and python_score >= 2:
        return True, "Code doesn't appear to be Java"
    
    if declared_lang == "javascript" and js_score == 0 and python_score >= 2:
        return True, "Code doesn't appear to be JavaScript"
    
    if declared_lang == "go" and go_score == 0 and python_score >= 2:
        return True, "Code doesn't appear to be Go"
    
    if declared_lang == "c" and cpp_score >= 2:
        return True, "Code contains C++ features but C was selected"
    
    return False, ""


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
    # print(f"[DEBUG] Language: {language}, Has input: {has_input}")
    return has_input


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
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "status": status,
        "time": f"{result['time_sec']}s",
        "memory": f"{result['memory_mb']}MB",
        "language": language
    }


def generate_test_cases_with_ai(code: str, language: str, provider_info: Dict) -> List[TestCase]:
    """AI-powered test case generator with multi-provider support"""
    if not provider_info:
        return []
    
    provider_type = provider_info["type"]
    client = provider_info["client"]
    model = provider_info["model"]
    
    print(f"Generating test cases using {provider_type} with model {model}...")
    
    system_prompt = """You are a test case generator. Generate 2-3 test cases for code.
Return ONLY a valid JSON array, no markdown, no explanation.
Format: [{"input":"value","expected_output":"value"}]
If code has no input, use empty string."""
    
    user_prompt = f"""Generate test cases for this {language.upper()} code:

```{language}
{code}
```

Rules:
- Return ONLY JSON array
- Use simple realistic values
- If multiple inputs: separate with \\n
- No markdown, no code blocks

JSON:"""
    
    try:
        if provider_type == "openai":
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=500,
            )
            content = completion.choices[0].message.content.strip()
        
        elif provider_type == "anthropic":
            message = client.messages.create(
                model=model,
                max_tokens=500,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
            )
            content = message.content[0].text.strip()
        
        elif provider_type == "huggingface":
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=500,
            )
            content = completion.choices[0].message.content.strip()
        
        else:
            return []
        
        print(f"Response received ({len(content)} chars)")
        
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        
        json_match = re.search(r'\[[\s\S]*\]', content)
        if json_match:
            content = json_match.group(0)
        else:
            return []
        
        test_data = json.loads(content)
        
        if not isinstance(test_data, list):
            return []
        
        test_cases = []
        for tc in test_data[:3]:
            if isinstance(tc, dict):
                test_cases.append(
                    TestCase(
                        input=str(tc.get("input", "")),
                        expected_output=str(tc.get("expected_output", ""))
                    )
                )
        
        print(f"Successfully generated {len(test_cases)} test cases")
        return test_cases
    
    except json.JSONDecodeError as e:
        print(f"JSON parsing failed: {e}")
        return []
    except Exception as e:
        print(f"Test generation failed: {str(e)}")
        return []


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


@app.post("/run")
def run_code(req: CodeRequest):
    """Main endpoint to execute code"""
    try:
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
        
        cleaned_code = sanitize_code(req.code)
        
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
        
        is_mismatch, mismatch_msg = detect_language_mismatch(cleaned_code, lang)
        if is_mismatch:
            return {
                "stdout": "",
                "stderr": f"Language mismatch: {mismatch_msg}. Please select the correct language.",
                "status": "error",
                "time": "0s",
                "memory": "0MB",
                "language": lang
            }
        
        needs_input = detect_input_requirement(cleaned_code, lang)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            fid = uuid.uuid4().hex
            
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
            
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(cleaned_code)
            
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
            
            cmd = get_execute_command(lang, src_path, exe_path, temp_dir, class_name)
            
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
            
            if not req.test_cases and not needs_input:
                return run_once(cmd, temp_dir, lang)
            
            test_cases = req.test_cases if req.test_cases else [TestCase(input="", expected_output="")]
            
            results = []
            total_time = 0
            max_memory = 0
            passed_count = 0
            
            for idx, tc in enumerate(test_cases, 1):
                input_data = tc.input if needs_input else ""
                expected = tc.expected_output or ""
                
                # print(f"Test {idx}: Sending input: {repr(input_data)}")
                
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
                    "input": tc.input,
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
