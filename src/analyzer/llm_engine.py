import requests
import json
import os

class LLMAnalyzer:
    def __init__(self, model_name: str = "llama3"):
        """
        Initializes the Large Language Model Engine for log analysis.
        Connects to the local Ollama instance running via Docker.
        """
        # Retrieves the host URL from environment variables, defaults to localhost for testing
        self.ollama_url = "http://localhost:11434"
        self.api_endpoint = f"{self.ollama_url}/api/generate"
        self.model_name = model_name

    def check_connection(self) -> bool:
        """
        Verifies the connection to the Ollama server.
        """
        try:
            response = requests.get(self.ollama_url, timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def generate_5w1h_report(self, log_entry: str) -> dict:
        """
        Transmits the captured log entry to the LLM and requests a structured 5W1H analysis.
        Returns the response as a parsed dictionary.
        """
        prompt = f"""
        You are an expert DevOps and Cybersecurity Diagnostic AI. 
        Your task is to analyze the provided system log entry and generate a root-cause analysis using the 5W1H framework.
        Maintain a highly professional, technical, and objective tone. Do not provide unnecessary conversational filler.

        TARGET LOG ENTRY:
        {log_entry}

        REQUIRED OUTPUT FORMAT (Return ONLY valid JSON):
        {{
            "WHAT": "Describe the core issue or event.",
            "WHERE": "Identify the file path, module, or component.",
            "WHO": "Identify the user, service, or process responsible.",
            "WHY": "Explain the technical reason for this log generation.",
            "HOW_TO_SOLVE": "Provide the exact technical remediation steps or commands."
        }}
        """

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json"  # Forces the LLM to return strict JSON for system integration
        }

        try:
            response = requests.post(self.api_endpoint, json=payload, timeout=60)
            response.raise_for_status()
            
            result_text = response.json().get("response", "{}")
            return json.loads(result_text)

        except requests.exceptions.RequestException as e:
            return {"error": f"Failed to connect to LLM Engine: {str(e)}"}
        except json.JSONDecodeError:
            return {"error": "LLM returned malformed data structure."}

# Independent testing block for the LLM Engine
if __name__ == "__main__":
    analyzer = LLMAnalyzer(model_name="llama3")
    
    print(f"[INFO] Connecting to AI Engine at {analyzer.ollama_url}...")
    
    if not analyzer.check_connection():
        print("[ERROR] AI Engine is unreachable. Ensure Ollama is running.")
        exit(1)

    print("[INFO] AI Engine is online. Running diagnostic test...")
    
    # Simulating a captured log entry from the collector
    sample_log = "[/var/log/syslog] Feb 22 15:45:01 api sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
    
    report = analyzer.generate_5w1h_report(sample_log)
    print("\n--- 5W1H DIAGNOSTIC REPORT ---")
    print(json.dumps(report, indent=4))