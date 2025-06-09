import os
import io
import re
import uuid
import json
from pydub import AudioSegment
from google.cloud import speech
import requests
import argparse
from dotenv import load_dotenv

# 인증 키 경로 설정
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "capstone2-461808-885e4052d835.json"

# 설정
parser = argparse.ArgumentParser()
parser.add_argument("--source", required=True, help="Path to source audio file (wav)")
args = parser.parse_args()
SOURCE_FILE = args.source
CHUNK_LENGTH_MS = 30 * 1000  # 30초 단위 (ms)

load_dotenv()
server_url = os.getenv("TEXT_MASKING_SERVER_URL")
MASK_CACHE_FILE = "masking_record.json"

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

def save_mask_cache():
    with open(MASK_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(MASK_CACHE, f, ensure_ascii=False, indent=2)

def split_audio(file_path, chunk_length_ms):
    audio = AudioSegment.from_wav(file_path)
    chunks = []
    for i in range(0, len(audio), chunk_length_ms):
        chunk = audio[i:i + chunk_length_ms]
        chunk_path = f"chunk_{i//chunk_length_ms}.wav"
        chunk.export(chunk_path, format="wav")
        chunks.append(chunk_path)
    return chunks

def transcribe_chunk(path):
    client = speech.SpeechClient()
    with io.open(path, 'rb') as audio_file:
        content = audio_file.read()

    audio = speech.RecognitionAudio(content=content)

    config = speech.RecognitionConfig(
        encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16,
        sample_rate_hertz=16000,
        language_code="ko-KR"
    )

    response = client.recognize(config=config, audio=audio)

    result_texts = []
    for result in response.results:
        result_texts.append(result.alternatives[0].transcript)
    return " ".join(result_texts)

def generate_uid():
    return str(uuid.uuid4())[:8]

def load_mask_tags_from_selection(file="selected_fields.json"):
    if not os.path.exists(file):
        return set()
    with open(file, "r", encoding="utf-8") as f:
        selections = json.load(f)
    tags = set()
    for sel in selections:
        tags.update(SELECTION_MASKING.get(sel, set()))
    return tags

def get_ner_result(text):
    try:
        response = requests.post(server_url, json={"text": text}, timeout=60)
        response.raise_for_status()
        return response.json()["ner_result"]
    except Exception as e:
        print(f"❌ 서버 요청 실패: {e}")
        return []

def mask_text_with_cache(text):
    mask_tags = load_mask_tags_from_selection()
    result = get_ner_result(text)
    masked_text = text

    global MASK_CACHE
    if os.path.exists(MASK_CACHE_FILE):
        with open(MASK_CACHE_FILE, "r", encoding="utf-8") as f:
            MASK_CACHE = json.load(f)

    def add_to_cache_and_replace(tag, word):
        uid = generate_uid()
        MASK_CACHE[uid] = (tag, word)
        return f"[{tag}_{uid}]"

    for word, tag in result:
        if tag in mask_tags and word in masked_text:
            masked_text = masked_text.replace(word, add_to_cache_and_replace(tag, word))

    if "EMAIL" in mask_tags:
        for email in re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', masked_text):
            masked_text = masked_text.replace(email, add_to_cache_and_replace("EMAIL", email))

    if "PHONE" in mask_tags:
        for phone in re.findall(r'01[016789]-\d{3,4}-\d{4}', masked_text):
            masked_text = masked_text.replace(phone, add_to_cache_and_replace("PHONE", phone))

    if "SSN" in mask_tags:
        for ssn in re.findall(r'\d{6}-\d{7}', masked_text):
            masked_text = masked_text.replace(ssn, add_to_cache_and_replace("SSN", ssn))

    save_mask_cache()
    return masked_text


def main():
    print("🔪 오디오 분할 중...")
    print("SOURCE_FILE 경로:", SOURCE_FILE)
    print("파일 존재 여부:", os.path.exists(SOURCE_FILE))
    chunk_paths = split_audio(SOURCE_FILE, CHUNK_LENGTH_MS)

    print("🗣️ 음성 인식 시작...\n")
    full_transcript = ""
    for i, chunk_path in enumerate(chunk_paths):
        print(f"🎧 조각 {i+1}/{len(chunk_paths)} 처리 중...")
        try:
            transcript = transcribe_chunk(chunk_path)
            print(f"📄 조각 {i+1} 텍스트: {transcript}\n")
            full_transcript += transcript + " "
        except Exception as e:
            print(f"❌ 조각 {i+1}에서 오류 발생: {e}")
        os.remove(chunk_path)

    print("📝 전체 텍스트 통합 결과:\n")
    print(full_transcript.strip())

    print("🛡️ 마스킹 중...")
    try:
        masked_sentence = mask_text_with_cache(full_transcript)
        print("✅ 마스킹 완료\n")
        print(masked_sentence)

        with open("masked_result.txt", "w", encoding="utf-8") as f:
            f.write(masked_sentence)

    except Exception as e:
        print("❌ 마스킹 실패:", e)
        return

if __name__ == "__main__":
    main()
