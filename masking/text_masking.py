import os
import json
import pyperclip
import time
import re
import uuid
import requests
from dotenv import load_dotenv

load_dotenv()
server_url = os.getenv("TEXT_MASKING_SERVER_URL")
SELECTION_MASKING = {
    "이름": {"PERSON"},
    "날짜": {"DATE"},
    "시간": {"TIME"},
    "장소": {"LOCATION"},
    "기관": {"ORGANIZATION"},
    "이메일": {"EMAIL"},
    "전화번호": {"PHONE"},
    "주민등록번호": {"SSN"}
}
MASK_CACHE = {}

def generate_uid():
    return str(uuid.uuid4())[:8]

def get_ner_result(text):
    try:
        response = requests.post(server_url, json={"text": text}, timeout=60)
        response.raise_for_status()
        return response.json()["ner_result"]
    except Exception as e:
        print(f"❌ 서버 요청 실패: {e}")
        return []
    
def load_mask_tags_from_selection(file="selected_fields.json"):
    if not os.path.exists(file):
        return set()
    with open(file, "r", encoding="utf-8") as f:
        user_selections = json.load(f)

    mask_tags = set()
    for sel in user_selections:
        mask_tags.update(SELECTION_MASKING.get(sel, set()))
    return mask_tags

def mask_text_with_cache(text):
    mask_tags = load_mask_tags_from_selection()
    result = get_ner_result(text)
    masked_text = text

    for word, tag in result:
        if tag in mask_tags and word in masked_text:
            uid = generate_uid()
            MASK_CACHE[uid] = (tag, word)
            masked_text = masked_text.replace(word, f"[{tag}_{uid}]")

    if "EMAIL" in mask_tags:
        for email in re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', masked_text):
            uid = generate_uid()
            MASK_CACHE[uid] = ("EMAIL", email)
            masked_text = masked_text.replace(email, f"[EMAIL_{uid}]")

    if "PHONE" in mask_tags:
        for phone in re.findall(r'01[016789]-\d{3,4}-\d{4}', masked_text):
            uid = generate_uid()
            MASK_CACHE[uid] = ("PHONE", phone)
            masked_text = masked_text.replace(phone, f"[PHONE_{uid}]")

    if "SSN" in mask_tags:
        for ssn in re.findall(r'\d{6}-\d{7}', masked_text):
            uid = generate_uid()
            MASK_CACHE[uid] = ("SSN", ssn)
            masked_text = masked_text.replace(ssn, f"[SSN_{uid}]")

    return masked_text

def partial_unmask(text):
    restored = text
    pattern = re.compile(r'\[([A-Z]+)_([a-f0-9]{8})\]')
    for tag, uid in pattern.findall(text):
        if uid in MASK_CACHE and MASK_CACHE[uid][0] == tag:
            word = MASK_CACHE[uid][1]
            restored = restored.replace(f"[{tag}_{uid}]", word)
    return restored

def main():
    print("📋 text_masking 클립보드 감시 중...")
    last_clip = pyperclip.paste()

    try:
        while True:
            current_clip = pyperclip.paste()

            if current_clip.strip() == "":
                time.sleep(0.3)
                continue

            if current_clip != last_clip:
                if re.search(r'\[([A-Z]+)_([a-f0-9]{8})\]', current_clip):
                    print("\n♻️ 마스킹된 텍스트 감지 → 역마스킹")
                    restored = partial_unmask(current_clip)
                    pyperclip.copy(restored)
                    print("✅ 복원 후 클립보드에 저장됨:\n", restored)
                    last_clip = restored
                    continue

                print("\n🔍 새 복사 감지!\n", current_clip)
                masked = mask_text_with_cache(current_clip)
                pyperclip.copy(masked)
                print("✅ 마스킹 후 클립보드에 저장됨:\n", masked)
                last_clip = masked

            time.sleep(0.5)

    except Exception as e:
        print(f"❌ 예외 발생: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
