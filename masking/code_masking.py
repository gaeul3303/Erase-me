import os
import json
import re
import pyperclip
import uuid
import time

masking_map = {}
MASK_CACHE_FILE = "masking_record.json"

def save_mask_cache():
    with open(MASK_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(masking_map, f, ensure_ascii=False, indent=2)

def load_mask_cache():
    global MASK_CACHE
    if os.path.exists(MASK_CACHE_FILE):
        with open(MASK_CACHE_FILE, "r", encoding="utf-8") as f:
            masking_map = json.load(f)

def generate_placeholder(label):
    return f"{label.upper()}_{uuid.uuid4().hex[:8]}"

def is_already_masked(value: str):
    return re.match(r'(KEY|URL|TOKEN|SECRET|USER|HOST|PATH)_[0-9a-f]{8}', value) is not None

def should_run_code_masking(config_file="selected_fields.json"):
    if not os.path.exists(config_file):
        return False
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            selected = json.load(f)
        return "변수" in selected
    except Exception as e:
        print(f"⚠️ 설정 파일 로딩 실패: {e}")
        return False

def mask_and_store(label, origin_value):
    if is_already_masked(origin_value):
        return origin_value

    placeholder = generate_placeholder(label)
    masking_map[placeholder] = origin_value

    if os.path.exists(MASK_CACHE_FILE):
        with open(MASK_CACHE_FILE, "r", encoding="utf-8") as f:
            prev_cache = json.load(f)
    else:
        prev_cache = {}

    prev_cache[placeholder] = origin_value

    with open(MASK_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(prev_cache, f, ensure_ascii=False, indent=2)

    return placeholder

def is_sensitive_value(value: str):
    if value.startswith("http"):
        return "url"
    if len(value) >= 8 and not value.isdigit():
        return "key"
    return None

def extract_url(text: str):
    pattern = r'((?:\w+\.)*\w+)\s*=\s*["\'](https?://[^\s"\']+)["\']'
    def replacer(match):
        key, value = match.group(1), match.group(2)
        label = is_sensitive_value(value)
        if label:
            placeholder = mask_and_store(label, value)
            return f'{key} = "{placeholder}"'
        return match.group(0)
    return re.sub(pattern, replacer, text)

def extract_keys(text: str):
    pattern = re.compile(r'((?:\w+\.)*\w*(KEY|TOKEN|SECRET)\w*)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    def replacer(match):
        keys, value = match.group(1), match.group(3)
        label = is_sensitive_value(value)
        if label:
            placeholder = mask_and_store(label, value)
            return f'{keys} = "{placeholder}"'
        return match.group(0)
    return re.sub(pattern, replacer, text)

def extract_define_Clang(text: str):
    pattern = re.compile(r'#define\s+(\w*(key|token|secret|url)\w*)\s+["\']([^"\']+)["\']', re.IGNORECASE)
    def replacer(match):
        key, value = match.group(1), match.group(3)
        label = is_sensitive_value(value)
        if label:
            placeholder = mask_and_store(label, value)
            return f'#define {key} "{placeholder}"'
        return match.group(0)
    return re.sub(pattern, replacer, text)

def extract_env_style(text: str):
    pattern = re.compile(r'(["\']?\w*(KEY|TOKEN|SECRET|URL)\w*["\']?)\s*[:=]\s*["\'](https?://[^\s"\']+|[^"\']{8,})["\']', re.IGNORECASE)
    def replacer(match):
        key, value = match.group(1), match.group(3)
        label = is_sensitive_value(value)
        if label:
            placeholder = mask_and_store(label, value)
            return f'{key}="{placeholder}"'
        return match.group(0)
    return re.sub(pattern, replacer, text)

_terminal_cache = {}
def mask_terminal(code) :
    lines = code.splitlines()
    masked_lines = []
    for line in lines :
        if line in _terminal_cache:
            masked_lines.append(_terminal_cache[line])
            continue
        origin_line = line
        line = mask_file_paths(line)
        
        mac_match = re.search(r"\((.*?)\)\s+(\w+)@([\w\-]+)\s+(.*?)\s*%",origin_line)
        if mac_match :
            env = mac_match.group(1)
            user = mac_match.group(2)
            host = mac_match.group(3)
            directory = mac_match.group(4).strip()
            
            masked_user = mask_and_store("user", user)
            masked_host = mask_and_store("host", host)
            masked_dir = mask_and_store("dir", directory)
            # % 이후 텍스트 추출
            # % 이후 텍스트 추출
            split_percent = origin_line.split("%", 1)
            post_percent = split_percent[1].strip() if len(split_percent) > 1 else ""
            # post_percent도 파일 경로 포함 가능 → 마스킹 처리
            masked_post = mask_file_paths(post_percent) if post_percent else ""
            masked_line = f"({env}) {masked_user}@{masked_host} {masked_dir} %"
            if masked_post:
                masked_line += f" {masked_post}"
            _terminal_cache[origin_line] = masked_line
            masked_lines.append(masked_line)
            continue
    
        win_match = re.match(r"([A-Z]):\\Users\\([^\\]+)\\(.+)>", line)
        if win_match :
            drive = win_match.group(1)
            user = win_match.group(2)
            path = win_match.group(3)
            
            masked_user = mask_and_store("user", user)
            masked_path = mask_and_store("path", path.replace("\\", "/"))
            print("User's WindowOS")
            masked_line = f"{drive}:\\Users\\{masked_user}\\{masked_path.replace('\\', '/')}>"
            _terminal_cache[line] = masked_line
            masked_lines.append(masked_line)
            continue
        
        masked_lines.append(line)
        
    return "\n".join(masked_lines)

def multi_mask(text: str, max_iter=10):
    prev = None
    current = text
    count = 0
    while prev != current and count < max_iter:
        prev = current
        current = extract_url(current)
        current = extract_keys(current)
        current = extract_define_Clang(current)
        current = extract_env_style(current)
        count += 1
    return current

def unmask(text: str):
    for placeholder, original in masking_map.items():
        text = text.replace(placeholder, original)
    return text

def has_masked_placeholder(text: str):
    return bool(re.search(r'(KEY|URL|TOKEN|SECRET|USER|HOST|PATH)_[0-9a-f]{8}', text))

def mask_file_paths(text):
    unix_pattern = re.compile(r'(/Users/[^ \n\r\t]*)')
    text = unix_pattern.sub(lambda m: mask_path_full(m.group(0)), text)
    win_pattern = re.compile(r'([A-Z]:\\Users\\[^\\\s]+(?:\\[^\\\s]+)*)')
    def win_replacer(m):
        path_slash = m.group(0).replace('\\', '/')
        masked = mask_path_full(path_slash)
        return masked.replace('/', '\\')
    text = win_pattern.sub(win_replacer, text)
    return text

def mask_path_full(path):
    
    parts = path.strip('/').split('/')
    if len(parts) < 2:
        return path  
    prefix = parts[0]
    user = parts[1]
    user_mask = mask_and_store("user", user)
    if len(parts) > 2:
        rest_path = '/'.join(parts[2:])
        folder_file_mask = mask_and_store("folder__file", rest_path)
    else:
        folder_file_mask = ""
    if folder_file_mask:
        return f"/{prefix}/{user_mask}/{folder_file_mask}"
    else:
        return f"/{prefix}/{user_mask}"
    
def main():
    if not should_run_code_masking():
        print("⚙️ '변수' 항목이 선택되지 않아 code_masking.py 종료됨.")
        return

    print("📋 code_masking 클립보드 감시 시작...")
    last_clip = pyperclip.paste()

    try:
        while True:
            current_clip = pyperclip.paste()

            if current_clip.strip() == "":
                time.sleep(0.3)
                continue

            if current_clip != last_clip:
                if has_masked_placeholder(current_clip):
                    print("\n♻️ 마스킹된 텍스트 감지 → 역마스킹")
                    load_mask_cache()
                    restored = unmask(current_clip)
                    pyperclip.copy(restored)
                    print("✅ 복원 후 클립보드에 저장됨:\n", restored)
                    last_clip = restored
                    continue

                print("\n🔍 새 복사 감지!\n", current_clip)
                terminal_masked = mask_terminal(current_clip)

                if terminal_masked != current_clip:
                    print("🖥️ 터미널 로그로 감지됨 → 마스킹 적용됨")
                    pyperclip.copy(terminal_masked)
                    print("✅ 마스킹된 터미널 로그 클립보드에 저장됨:\n", terminal_masked)
                    last_clip = terminal_masked
                    continue
                masked = multi_mask(current_clip)
                pyperclip.copy(masked)
                print("✅ 마스킹 후 클립보드에 저장됨:\n", masked)
                last_clip = masked

            time.sleep(0.5)

    except Exception as e:
        print(f"❌ 예외 발생: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
