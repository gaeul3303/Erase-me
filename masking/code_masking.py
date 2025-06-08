import os
import json
import re
import pyperclip
import uuid
import time

masking_map = {}

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
    if origin_value in masking_map.values():
        for k, v in masking_map.items():
            if v == origin_value:
                return k
    placeholder = generate_placeholder(label)
    masking_map[placeholder] = origin_value
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

def mask_terminal(code: str):
    mac_match = re.search(r"\((.*?)\)\s+(\w+)@([\w\-]+)", code)
    if mac_match:
        env, user, host = mac_match.groups()
        masked_user = mask_and_store("user", user)
        masked_host = mask_and_store("host", host)
        return f"({env}) {masked_user}@{masked_host} %"

    win_match = re.match(r"([A-Z]):\\Users\\([^\\]+)\\(.+)>", code)
    if win_match:
        drive, user, path = win_match.groups()
        masked_user = mask_and_store("user", user)
        masked_path = mask_and_store("path", path.replace("\\", "/"))
        return f"{drive}:\\Users\\{masked_user}\\{masked_path}>"
    return code

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
        current = mask_terminal(current)
        count += 1
    return current

def unmask(text: str):
    for placeholder, original in masking_map.items():
        text = text.replace(placeholder, original)
    return text

def has_masked_placeholder(text: str):
    return bool(re.search(r'(KEY|URL|TOKEN|SECRET|USER|HOST|PATH)_[0-9a-f]{8}', text))

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
                    restored = unmask(current_clip)
                    pyperclip.copy(restored)
                    print("✅ 복원 후 클립보드에 저장됨:\n", restored)
                    last_clip = restored
                    continue

                print("\n🔍 새 복사 감지!\n", current_clip)
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
