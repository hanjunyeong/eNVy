"""Submit a local file without executing it; inspect queued/cache result."""
import argparse
from pathlib import Path
import time
import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=60, trust_env=False) as client:
        started = time.perf_counter()
        with args.file.open("rb") as source:
            response = client.post("/scan", files={"file": (args.file.name, source, "application/octet-stream")})
        response.raise_for_status()
        job = response.json()
        print("Accepted:", job["job_id"], job["status"])
        deadline = time.monotonic() + 2400
        while job["status"] not in {"succeeded", "failed"}:
            if time.monotonic() > deadline:
                raise SystemExit("Stopped waiting; query /jobs/ID or the UI history later")
            time.sleep(1)
            response = client.get("/jobs/" + job["job_id"])
            response.raise_for_status()
            job = response.json()
            print("Stage:", job.get("stage"))
        print("Status:", job["status"], "source:", job.get("result_source"))
        if job.get("result"):
            print("Score:", job["result"]["score"], "verdict:", job["result"]["verdict"])
        else:
            print("Error:", job.get("error"))
        print(f"Upload-to-result elapsed: {time.perf_counter()-started:.3f} seconds")


if __name__ == "__main__":
    main()
