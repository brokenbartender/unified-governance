import time
import json
import urllib.request

BASE_URL = "http://127.0.0.1:8000"
API_KEY = "YOUR_API_KEY"


def post(path, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode("utf-8")


def main():
    start = time.time()
    for _ in range(100):
        post("/evaluations", {
            "policy_id": "POLICY_ID",
            "principal": "user",
            "action": "read",
            "resource_id": "RESOURCE_ID"
        })
    elapsed = time.time() - start
    print(f"100 evals in {elapsed:.2f}s")


if __name__ == "__main__":
    main()
