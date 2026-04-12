import httpx
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor

API_URL = "http://localhost:8000"

def test_endpoint(endpoint, method="GET", data=None):
    try:
        start = time.time()
        if method == "GET":
            response = httpx.get(f"{API_URL}{endpoint}", timeout=10)
        else:
            response = httpx.post(f"{API_URL}{endpoint}", json=data, timeout=10)
        elapsed = time.time() - start
        return {"endpoint": endpoint, "status": response.status_code, "time": elapsed}
    except Exception as e:
        return {"endpoint": endpoint, "error": str(e)[:50]}

def run_tests(count):
    print(f"Running stress test with {count} requests per endpoint...\n")
    
    tests = [
        ("/api/v1/status", "GET"),
        ("/api/v1/devices", "GET"),
        ("/api/v1/alerts", "GET"),
        ("/api/v1/dns/blocked", "GET"),
        ("/api/v1/plugins", "GET"),
        ("/api/v1/honeypot/services", "GET"),
        ("/api/v1/honeypot/stats", "GET"),
    ]
    
    results = []
    start_time = time.time()
    
    for _ in range(count):
        for endpoint, method in tests:
            result = test_endpoint(endpoint, method)
            results.append(result)
    
    total_time = time.time() - start_time
    
    success = sum(1 for r in results if r.get("status") == 200)
    failed = len(results) - success
    avg_time = sum(r.get("time", 0) for r in results) / len(results)
    
    print("=" * 50)
    print("STRESS TEST RESULTS")
    print("=" * 50)
    print(f"Total requests: {len(results)}")
    print(f"Successful: {success}")
    print(f"Failed: {failed}")
    print(f"Success rate: {success/len(results)*100:.1f}%")
    print(f"Total time: {total_time:.2f}s")
    print(f"Requests/sec: {len(results)/total_time:.1f}")
    print(f"Avg response time: {avg_time*1000:.1f}ms")
    print("=" * 50)

if __name__ == "__main__":
    run_tests(20)
