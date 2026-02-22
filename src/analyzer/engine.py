import requests
import json

class NativeAIAnalyzer:
    def __init__(self, model="llama3"):
        self.url = "http://localhost:11434/api/generate"
        self.model = model

    def analyze_event(self, cmd, exit_code, pid):

        prompt = f"Diagnostic report for Linux failure: CMD:{cmd}, EXIT_CODE:{exit_code}. Explain Why it failed and How to fix it in 5W1H JSON format."
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "num_predict": 150,
                "top_k": 20,
                "top_p": 0.5
            }
        }

        try:

            response = requests.post(self.url, json=payload, timeout=120)
            response.raise_for_status()
            result_text = response.json().get("response", "{}")
            return json.loads(result_text)
        except Exception as e:
            return {"error": f"AI Engine Connection Failed: {str(e)}"}
