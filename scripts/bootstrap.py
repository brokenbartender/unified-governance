import argparse
import json
import urllib.request


def request(base_url, api_key, path, method="POST", payload=None):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    data = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", required=True)
    args = parser.parse_args()

    org = request(args.base_url, args.api_key, "/orgs", payload={"name": "Demo Org"})
    key = request(args.base_url, args.api_key, f"/orgs/{org['id']}/keys", payload={"name": "demo-key"})
    print(json.dumps({"org": org, "key": key}, indent=2))


if __name__ == "__main__":
    main()
