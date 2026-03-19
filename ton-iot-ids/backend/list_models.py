import os, json
from dotenv import load_dotenv # type: ignore
import google.generativeai as genai # type: ignore

load_dotenv()
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))

try:
    models = genai.list_models()
    names = [m.name for m in models if 'generateContent' in m.supported_generation_methods]
    with open('models.json', 'w') as f:
        json.dump(names, f)
except Exception as e:
    print("Error:", e)
