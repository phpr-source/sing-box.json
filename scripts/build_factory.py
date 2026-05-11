import json
import os
import subprocess
import sys
import concurrent.futures
import re
import shutil
from datetime import datetime

CONFIG_REMOTE = 'remote-rules.json'
DIR_OUTPUT = 'rules'
DIR_SRC = 'src'
MAX_WORKERS = 5

RULE_MAP = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix',
    'DOMAIN': 'domain', 'HOST': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword',
    'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip', 'DST-PORT': 'port', 'SRC-PORT': 'source_port',
    'PROCESS-NAME': 'process_name'
}

REPO_RAW_BASE = 'https://raw.githubusercontent.com/phpr-source/sing-box.json/main'

class TaskResult:
    def __init__(self, name, status, msg, size="0KB"):
        self.name, self.status, self.msg, self.size = name, status, msg, size

def setup_directories():
    for d in [DIR_OUTPUT, DIR_SRC]:
        if not os.path.exists(d):
            os.makedirs(d)

def get_core_version():
    if not os.path.exists("./sing-box"):
        return "N/A"
    try:
        res = subprocess.run(["./sing-box", "version"], capture_output=True, text=True)
        line = res.stdout.split('\n')[0] if res.stdout else ""
        return line.split('version ')[-1].strip() if 'version ' in line else "unknown"
    except Exception:
        return "unknown"

def get_file_size(filepath):
    if not os.path.exists(filepath):
        return "0KB"
    size = os.path.getsize(filepath)
    for unit in ['B', 'KB', 'MB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"

def download_file(url, filename):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    cmd = ["curl", "-L", "--fail", "--retry", "3", "-A", ua, url, "-o", filename]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except Exception:
        return False

def optimize_json_file(filepath, format_version):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        data['version'] = format_version
        rules = data.get('rules', [])
        total_removed = 0
        for rule in rules:
            keys_to_del = []
            for k, v in rule.items():
                if isinstance(v, list):
                    new_v = sorted(list(set(v)))
                    if len(new_v) != len(v):
                        total_removed += len(v) - len(new_v)
                    rule[k] = new_v
                    if not new_v:
                        keys_to_del.append(k)
            for k in keys_to_del:
                del rule[k]
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True, total_removed
    except Exception:
        return False, 0

def convert_clash_to_json(input_file, output_json):
    rules_dict = {v: set() for v in set(RULE_MAP.values())}
    count = 0
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith(('#', '//')):
                continue
            line = re.split(r'\s*(#|//)', line)[0].strip()
            match = re.search(r'^([A-Z0-9-]+)\s*,\s*([^,]+)', line, re.IGNORECASE)
            if match:
                type_, val = match.group(1).upper(), match.group(2).strip().strip("'\"")
                if type_ in RULE_MAP:
                    rules_dict[RULE_MAP[type_]].add(val)
                    count += 1
        if count == 0:
            return False, "No valid rules"
        final = [{k: sorted(list(v))} for k, v in rules_dict.items() if v]
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump({"version": 1, "rules": final}, f, ensure_ascii=False, indent=2)
        return True, f"Conv {count}"
    except Exception as e:
        return False, str(e)

def find_local_sources():
    """自動掃描 src/ 目錄，發現所有本地規則文件。"""
    sources = {}
    if not os.path.exists(DIR_SRC):
        return sources
    for f in sorted(os.listdir(DIR_SRC)):
        if f.endswith('.json'):
            name = f[:-5]
            sources[name] = os.path.join(DIR_SRC, f)
    if sources:
        print(f"📁 Discovered local sources from {DIR_SRC}/: {', '.join(sources.keys())}")
    return sources

def process_remote_rule(name, url, format_version):
    print(f"🔄 [{name}] Processing remote...")
    tmp = f"temp_{name}"
    f_json = os.path.join(DIR_OUTPUT, f"{name}.json")
    f_srs = os.path.join(DIR_OUTPUT, f"{name}.srs")

    if not download_file(url, tmp):
        return TaskResult(name, "❌", "Download Failed")

    json_ready, msg = False, "Unknown"
    try:
        url_l = url.lower()
        if url_l.endswith('.srs'):
            subprocess.run(["./sing-box", "rule-set", "decompile", tmp, "-o", f_json], check=True)
            msg, json_ready = "SRS Rebuilt", True
        elif url_l.endswith('.json'):
            shutil.move(tmp, f_json)
            msg, json_ready = "JSON Native", True
        elif url_l.endswith('.mrs'):
            return TaskResult(name, "❌", "MRS Not Supported")
        else:
            ok, m = convert_clash_to_json(tmp, f_json)
            if ok:
                msg, json_ready = "Converted", True
            else:
                return TaskResult(name, "❌", m)
    except Exception:
        return TaskResult(name, "❌", "Process Error")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    if json_ready:
        ok, n = optimize_json_file(f_json, format_version)
        if ok:
            msg += f" (Opt {n})"
        try:
            subprocess.run(["./sing-box", "rule-set", "compile", f_json, "-o", f_srs], check=True)
            return TaskResult(name, "✅", msg, get_file_size(f_srs))
        except Exception:
            return TaskResult(name, "❌", "Compile Failed")
    return TaskResult(name, "❌", "Logic Error")

def process_local_rule(name, source_path, format_version):
    print(f"📄 [{name}] Processing local...")
    f_srs = os.path.join(DIR_OUTPUT, f"{name}.srs")
    f_json = os.path.join(DIR_OUTPUT, f"{name}.json")

    if not os.path.exists(source_path):
        return TaskResult(name, "❌", f"Source not found: {source_path}")

    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return TaskResult(name, "❌", "Invalid JSON source")

    data['version'] = format_version
    try:
        with open(f_json, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        return TaskResult(name, "❌", "Write Failed")

    try:
        subprocess.run(["./sing-box", "rule-set", "compile", f_json, "-o", f_srs], check=True)
        return TaskResult(name, "✅", f"Local v{format_version}", get_file_size(f_srs))
    except Exception:
        return TaskResult(name, "❌", "Compile Failed")

def cleanup_outputs(remote_tasks, local_tasks):
    """清理 rules/ 中的已知產物，只刪除會被重建的文件。"""
    all_keys = set(remote_tasks.keys()) | set(local_tasks.keys())
    for key in all_keys:
        for ext in ['.json', '.srs']:
            f = os.path.join(DIR_OUTPUT, f"{key}{ext}")
            if os.path.exists(f):
                os.remove(f)
                print(f"🧹 Cleaned: {f}")
    readme = os.path.join(DIR_OUTPUT, "README.md")
    if os.path.exists(readme):
        os.remove(readme)

def generate_full_readme(core_ver, format_version):
    print("📝 Generating README...")
    files = sorted([f for f in os.listdir(DIR_OUTPUT) if f.endswith('.srs')])
    with open(os.path.join(DIR_OUTPUT, "README.md"), 'w', encoding='utf-8') as f:
        f.write(f"# 📦 Sing-box Rule Set Collection\n\n")
        f.write(f"> **Core**: `{core_ver}` | **Format**: `{format_version}` | **Updated**: `{datetime.now().strftime('%Y-%m-%d %H:%M')}`\n\n")
        f.write("| Rule Name | SRS (Binary) | Source (JSON) | Size |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        for srs in files:
            name = srs[:-4]
            json_name = f"{name}.json"
            json_exists = os.path.exists(os.path.join(DIR_OUTPUT, json_name))
            srs_url = f"{REPO_RAW_BASE}/rules/{srs}"
            json_url = f"{REPO_RAW_BASE}/rules/{json_name}" if json_exists else "-"
            size = get_file_size(os.path.join(DIR_OUTPUT, srs))
            f.write(f"| **{name}** | [{srs}]({srs_url}) | {f'[{json_name}]({json_url})' if json_exists else '-'} | {size} |\n")

def resolve_format_version():
    env_val = os.getenv('FORMAT_VERSION', '').strip()
    if env_val and env_val.isdigit():
        return int(env_val)
    try:
        src = subprocess.run(
            ["curl", "-sL", "--retry", "3",
             "https://raw.githubusercontent.com/reF1nd/sing-box/refs/heads/reF1nd-testing/constant/rule.go"],
            capture_output=True, text=True
        )
        m = re.search(r'RuleSetVersionCurrent\s*=\s*RuleSetVersion(\d+)', src.stdout)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 5

def load_config(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content:
                return json.loads(content)
    except Exception:
        pass
    return {}

def main():
    args = [a for a in sys.argv[1:]]
    fmt_ver = resolve_format_version()
    print(f"Target format version: {fmt_ver}")

    setup_directories()
    core_ver = get_core_version()
    print(f"Core version: {core_ver}")

    remote_tasks = {}
    local_tasks = {}

    if len(args) >= 2:
        remote_tasks[args[0]] = args[1]
        print(f"Manual task: {args[0]} → {args[1]}")
    else:
        remote_tasks = load_config(CONFIG_REMOTE)
        local_tasks = find_local_sources()

    cleanup_outputs(remote_tasks, local_tasks)

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for name, url in remote_tasks.items():
            futures[executor.submit(process_remote_rule, name, url, fmt_ver)] = name
        for name, path in local_tasks.items():
            futures[executor.submit(process_local_rule, name, path, fmt_ver)] = name
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    gen_readme = '--gen-readme' in args
    if gen_readme:
        generate_full_readme(core_ver, fmt_ver)

    github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
    if results and github_step_summary:
        with open(github_step_summary, 'a', encoding='utf-8') as f:
            f.write(f"## 🏭 Report\n- **Core**: `{core_ver}` | **Format**: `{fmt_ver}`\n")
            for r in results:
                f.write(f"- {r.status} {r.name}: {r.msg}\n")

    if any(r.status == "❌" for r in results):
        print("❌ Some tasks failed. Exiting with error to prevent partial commit.")
        sys.exit(1)

if __name__ == "__main__":
    main()
