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

SUPPORTED_LANGUAGES = ["python", "c", "cpp", "java"]
MAX_CODE_SIZE = 10000
MAX_EXECUTION_TIME = 5
MAX_MEMORY_MB = 150

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

def validate_code_security(code: str) -> tuple[bool, str]:
    if len(code) > MAX_CODE_SIZE:
        return False, f"Code too large. Maximum {MAX_CODE_SIZE} characters allowed."
    code_lower = code.lower()
    for keyword in FORBIDDEN_KEYWORDS:
        if re.search(r"\b" + re.escape(keyword), code_lower):
            return False, f"Security violation: '{keyword}' is not allowed."
    suspicious_patterns = [
        r"__.*__", r"import\s+\*", r"exec\s*\(", r"eval\s*\(", r"__import__\s*\("
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, code_lower):
            return False, f"Security violation: Pattern '{pattern}' is not allowed."
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
    try:
        preexec_fn = set_resource_limits if HAS_RESOURCE and os.name != "nt" else None
        kwargs = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
                  "stderr": subprocess.PIPE, "text": True, "cwd": temp_dir,
                  "preexec_fn": preexec_fn}
        proc = subprocess.Popen(cmd, **kwargs)

        try:
            stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
            return type("Result", (), {"returncode": proc.returncode,
                                       "stdout": stdout, "stderr": stderr})()
        except subprocess.TimeoutExpired:
            # Kill the process and children
            if HAS_PSUTIL:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            else:
                if os.name != "nt":
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            return type("Result", (), {"returncode": -1,
                                       "stdout": "", "stderr": "Timeout expired"})()
    except Exception as e:
        return type("Result", (), {"returncode": -1, "stdout": "", "stderr": str(e)})()

@app.post("/run")
def run_code(req: CodeRequest):
    try:
        lang = req.language.lower()
        if lang not in SUPPORTED_LANGUAGES:
            raise HTTPException(status_code=400, detail="Unsupported language")

        is_safe, err = validate_code_security(req.code)
        if not is_safe:
            raise HTTPException(status_code=400, detail=err)

        cleaned_code = sanitize_code(req.code)
        if lang == "cpp" and "def " in cleaned_code:
            return {"error": "Language mismatch", "details": "Looks like Python but selected C++"}
        if lang == "python" and "#include" in cleaned_code:
            return {"error": "Language mismatch", "details": "Looks like C/C++ but selected Python"}

        with tempfile.TemporaryDirectory() as temp_dir:
            fid = uuid.uuid4().hex
            class_name = extract_java_class_name(cleaned_code) if lang == "java" else None

            filename = {
                "python": f"{fid}.py",
                "c": f"{fid}.c",
                "cpp": f"{fid}.cpp",
                "java": f"{class_name}.java"
            }[lang]

            src_path = os.path.join(temp_dir, filename)
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(cleaned_code)

            exe_path = os.path.join(temp_dir, fid + (".exe" if os.name == "nt" else ""))

            needs_input = bool(re.search(r"\b(input|scanf|cin|Scanner)\b", cleaned_code))
            nondet = any(tok in cleaned_code for tok in ("random","time(","datetime","now()","currentTimeMillis","Math.random"))

            # Test cases
            test_cases = []
            if req.auto_generate:
                if nondet:
                    return {"warning": "Code contains randomness, skipping test validation.",
                            "raw_output": run_once(lang, src_path, exe_path, temp_dir, class_name)}
                test_cases = generate_test_cases(cleaned_code, lang)
            elif req.manual_cases:
                for i in range(0, len(req.manual_cases or []), 2):
                    inp = req.manual_cases[i]
                    exp = req.manual_cases[i+1] if i+1 < len(req.manual_cases) else ""
                    test_cases.append({"input": inp, "expected_output": exp})

            # Compile if C/C++/Java
            if lang in ("c","cpp"):
                compiler = shutil.which("gcc") if lang=="c" else shutil.which("g++")
                if not compiler:
                    return {"error": "Compiler not found", "details": f"{lang.upper()} compiler not installed"}
                cp = run_with_timeout([compiler, src_path, "-o", exe_path], timeout=10)
                if cp.returncode != 0:
                    return {"error": "Compilation failed", "details": cp.stderr}

            elif lang == "java":
                cp = run_with_timeout(["javac", src_path], timeout=10)
                if cp.returncode != 0:
                    return {"error": "Compilation failed", "details": cp.stderr}

            if not test_cases and not needs_input:
                return {"language": lang, "raw_output": run_once(lang, src_path, exe_path, temp_dir, class_name)}

            if not test_cases:
                test_cases = [{"input": "", "expected_output": ""}]

            results, passed, total_time = [], 0, 0.0
            for tc in test_cases:
                inp = tc["input"].strip() + "\n" if needs_input else ""
                exp = tc["expected_output"]
                cmd = get_command(lang, src_path, exe_path, temp_dir, class_name)
                start = time.time()
                proc = run_with_timeout(cmd, inp, MAX_EXECUTION_TIME)
                dur = round(time.time()-start,3)
                actual = clean_output(proc.stdout)
                expected = clean_output(exp)
                ok = "N/A" if nondet else (actual == expected)
                if ok is True: passed+=1
                results.append({"input": tc["input"], "expected_output": exp,
                                "actual_output": actual, "passed": ok, "time": dur})

            return {"language": lang, "total": len(results) if not nondet else "N/A",
                    "passed": passed if not nondet else "N/A",
                    "execution_time": round(total_time,3), "results": results}

    except Exception as e:
        traceback.print_exc()
        return {"error": "Internal server error", "details": str(e)}

# --------- Utility Functions ---------
def sanitize_code(code:str)->str:
    return code.replace("\u00a0"," ").replace("\u202f"," ").replace("\u200b","")

def get_command(lang, src_path, exe_path, tmp_dir, class_name=None):
    if lang=="python":
        return [sys.executable,"-u","-E","-S",src_path]
    if lang in ("c","cpp"):
        return [exe_path]
    if lang=="java":
        return ["java","-cp",tmp_dir,class_name]

def run_once(lang, src_path, exe_path, temp_dir, class_name=None):
    cmd = get_command(lang, src_path, exe_path, temp_dir, class_name)
    proc = run_with_timeout(cmd, timeout=MAX_EXECUTION_TIME, temp_dir=temp_dir)
    output = (proc.stdout or "").strip()
    if proc.stderr: output+="\n"+proc.stderr.strip()
    return output

def clean_output(text:str)->str:
    return re.sub(r"Enter\s+[^:]*:\s*","", text, flags=re.I).strip()

def generate_test_cases(code:str, language:str)->List[dict]:
    prompt = f"""
You are a test case generator. Given this {language.upper()} code, return exactly 2 test cases in JSON format:
[{{"input":"...","expected_output":"..."}},{{"input":"...","expected_output":"..."}}]
If the code has no input(), leave "input" empty. Only return valid JSON.
Code:
{code}
"""
    try:
        resp = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role":"user","content":prompt}],
            temperature=0.2,
            request_timeout=10
        )
        return json.loads(resp.choices[0].message.content.strip())
    except Exception:
        return [{"input":"","expected_output":""}]
