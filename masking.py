import re
import pyperclip
import uuid
import argparse
import json
import os
# 단순한 숫자 제외
# 중요한 코드 숫자
# 따로 저장 파일 
MAPPING_FILE = "masking_map.json"
# 중요한 정보에 대해서 따로 보관하는 매핑 딕셔너리
masking_map = {}

# uuid기반 key생성
def generate_placeholder(label):
    return f"{label.upper()}_{uuid.uuid4().hex[:8]}"

# 마스킹정보 중복 저장 방지
def is_already_masked(value: str):
    return re.match(r'(KEY|URL|TOKEN|SECRET)_[0-9a-f]{8}', value) is not None

# 정보에 대해서 매핑 저장
def mask_and_store(label, origin_value):
    if is_already_masked(origin_value):
        return origin_value
    if origin_value in masking_map:
        return masking_map[origin_value]
    placeholder = generate_placeholder(label)
    masking_map[placeholder] = origin_value
    return placeholder

# 딕셔너리 안에 키 값이 원본 데이터인 경우만 filtering
def filter_invalid_key(data):
    valid_keys = set(data.values())
    return {k: v for k, v in data.items() if v in valid_keys or k.startswith(('URL_', 'KEY_'))}

def is_sensitive_value(value : str):
    if value.startswith("http"):
        return "url"
    if len(value) >= 8 and not value.isdigit():
        return "key"
    return None

# url 추출 
def extract_url(text: str):
    # (추가) 객체 속성
    pattern = r'((?:\w+\.)*\w+)\s*=\s*["\'](https?://[^\s"\']+)["\']'
    def replacer(match):
        url = match.group(1)
        value = match.group(2)
        label = is_sensitive_value(value)
        if label:
            placeholder = mask_and_store(label, value)
            return f'{url} = "{placeholder}"'
        return match.group(0)
    replaced_code = re.sub(pattern, replacer, text)
    return replaced_code

# key/token 마스킹
def extract_keys (text : str):
    # 중요한 key에 대한 정규식 
    # (추가) 대소문자 구분없이 
    key_pattern = re.compile(r'((?:\w+\.)*\w*(KEY|TOKEN|SECRET)\w*)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    def replacer(match):
        #print(f'[extract_keys] 감지됨: "{match.group(0)}"')
        keys = match.group(1)
        value = match.group(3)
        label = is_sensitive_value(value)
        if label:
            placeholder = mask_and_store(label, value)
            return f'{keys} = "{placeholder}"'
        return match.group(0)
    replaced_code = re.sub(key_pattern, replacer, text)
    return  replaced_code

# C계열의 전처리_define
def extract_define_Clang (text: str) :
    define_pattern = re.compile(r'#define\s+(\w*(key|token|secret|url)\w*)\s+["\']([^"\']+)["\']', re.IGNORECASE)
    def replacer(match):
        key = match.group(1)
        value = match.group(3)
        label = is_sensitive_value(value)
        if label:
            placeholder = mask_and_store(label, value)
            return f'#define {key} "{placeholder}"'
        return match.group(0)  # 그대로 두기
    
    replaced_code = define_pattern.sub(replacer, text)
    return replaced_code

# .env 처럼 객체 형식으로 된 것
def extract_env_style(text: str):
    
    pattern = re.compile(r'(["\']?\w*(KEY|TOKEN|SECRET|URL)\w*["\']?)\s*[:=]\s*["\'](https?://[^\s"\']+|[^"\']{8,})["\']', re.IGNORECASE)
    
    def replacer(match):
        key = match.group(1)
        value = match.group(3)
        label = is_sensitive_value(value)
        if label:
            placeholder = mask_and_store(label, value)
            return f'{key}="{placeholder}"'
        '''
        if value.startswith("http"):
            return f'{key} = important_url'
        elif len(value) >= 8 and not value.isdigit():
            return f'{key} = "important_key"'
        
        '''
        return match.group(0)  # 일반적인 값은 그대로 두기

    replaced_code = pattern.sub(replacer, text)
    return replaced_code

'''
# 반복작업
def multi_mask (text: str) :
    print("muti_mask 진입")
    prev = None
    current = text
    while prev != current:
        prev = current
        current = extract_url(current)
        current = extract_keys(current)
        current = extract_define_Clang(current)
        current = extract_env_style(current)
    return current
'''
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

# 역마스킹 실행
def unmask(text: str):
    if not os.path.exists(MAPPING_FILE):
        print("⚠️ 복원용 매핑 파일이 존재하지 않습니다.")
        return text

    with open(MAPPING_FILE, "r") as f:
        saved_map = json.load(f)
    for placeholder, original in saved_map.items():
        text = text.replace(placeholder, original)
    return text

# 매핑 저장
def save_mapping_file():
    with open(MAPPING_FILE, "w") as f :
        json.dump(masking_map, f, indent=2)
# macOS terminal
#[mac 환경]
#(base) koojayeon@gujayeon-ui-MacBookAir Extract_Code % 
#[window 환경]
#C:\Users\johnsmith\Documents\Projects\AI> 

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

#terminal에서 Unix 형태의 경로가 있는 경우에 다시 마스킹

def mask_path_full(path):
    """
    /Users/koojayeon/Extract_Code/masking.py
    -> /Users/<user_mask>/<folder__file_mask>
    """
    parts = path.strip('/').split('/')
    # parts 예: ['Users', 'koojayeon', 'Extract_Code', 'masking.py']

    if len(parts) < 2:
        return path  # 예상외 형태면 그냥 리턴

    # Users는 그대로 유지
    prefix = parts[0]
    user = parts[1]
    # 사용자명 마스킹
    user_mask = mask_and_store("user", user)

    # 나머지 경로 폴더+파일 합쳐서 마스킹
    if len(parts) > 2:
        rest_path = '/'.join(parts[2:])
        folder_file_mask = mask_and_store("folder__file", rest_path)
    else:
        folder_file_mask = ""

    if folder_file_mask:
        return f"/{prefix}/{user_mask}/{folder_file_mask}"
    else:
        return f"/{prefix}/{user_mask}"



def mask_file_paths(text):
    # Unix 경로 예: /Users/username/...
    unix_pattern = re.compile(r'(/Users/[^ \n\r\t]*)')

    text = unix_pattern.sub(lambda m: mask_path_full(m.group(0)), text)
    win_pattern = re.compile(r'([A-Z]:\\Users\\[^\\\s]+(?:\\[^\\\s]+)*)')
    # Windows 경로 예: C:\Users\username\...
    def win_replacer(m):
        path_slash = m.group(0).replace('\\', '/')
        masked = mask_path_full(path_slash)
        return masked.replace('/', '\\')
    text = win_pattern.sub(win_replacer, text)

    return text

# 실행 함수
def main():

    code = pyperclip.paste()
    terminal_masked = mask_terminal(code)
    
    if terminal_masked != code:
        print("마스킹된 터미널:\n", terminal_masked)
        global masking_map
        masking_map = filter_invalid_key(masking_map)
        save_mapping_file()
        pyperclip.copy(terminal_masked)
        return
    masked = multi_mask(code)
    print("마스킹된 코드:\n", masked)
    if masked != code:
        masking_map = filter_invalid_key(masking_map)
        save_mapping_file()
        pyperclip.copy(masked)
    else:
        print("민감 정보 없음")

if __name__ == "__main__":
    main()
