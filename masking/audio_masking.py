import os
import io
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

def send_to_ner(full_text):
    response = requests.post(server_url, json={"text": full_text}, timeout=60)
    response.raise_for_status()
    data = response.json()
    if "ner_result" not in data:
        raise ValueError("ner_result 없음")
    return data["ner_result"]

def render_masked_sentence(ner_result):
    output = []
    for word, tag in ner_result:
        if tag != "O":
            output.append(f"{{{tag}}}")
        else:
            output.append(word)
    return "".join(output).replace("  ", " ").strip()

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
    print("NER 서버 요청 중...")
    try:
        ner_result = send_to_ner(full_transcript)
        print("마스킹 결과 수신 완료")
        masked_sentence = render_masked_sentence(ner_result)
        print("\n🛡️ 마스킹된 문장:\n", masked_sentence)
        with open("masked_result.txt", "w", encoding="utf-8") as f:
            f.write(masked_sentence)
    except Exception as e:
        print(" 마스킹 실패:", e)
    
        return

if __name__ == "__main__":
    main()
