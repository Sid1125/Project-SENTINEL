import httpx
import json

payload = {
    "model": "phi:latest",
    "messages": [
        {"role": "system", "content": "You are a cybersecurity analyst."},
        {"role": "user", "content": "Analyze this SSH attack: commands='user admin'"}
    ],
    "stream": False
}

try:
    with httpx.Client(timeout=60.0) as client:
        response = client.post("http://localhost:11434/api/chat", json=payload)
        print("Status:", response.status_code)
        print("Response text:", response.text[:500])
except Exception as e:
    print("Error:", e)
