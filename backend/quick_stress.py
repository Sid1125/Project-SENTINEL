import httpx
import time

API_URL = "http://localhost:8000"

def test_endpoint(endpoint):
    try:
        start = time.time()
        response = httpx.get(f"{API_URL}{endpoint}", timeout=5)
        elapsed = time.time() - start
        return {"endpoint": endpoint, "status": response.status_code, "time": elapsed}
    except Exception as e:
        return {"endpoint": endpoint, "error": str(e)[:30]}

if __name__ == "__main__":
    print("Quick Stress Test - 10 requests per endpoint\n")
    
    tests = [
        "/api/v1/status",
        "/api/v1/devices", 
        "/api/v1/alerts",
        "/api/v1/dns/blocked",
        "/api/v1/plugins",
        "/api/v1/honeypot/services",
    ]
    
    results = []
    start_time = time.time()
    
    for _ in range(10):
        for endpoint in tests:
            result = test_endpoint(endpoint)
            results.append(result)
    
    total_time = time.time() - start_time
    
    success = sum(1 for r in results if r.get("status") == 200)
    print(f"Results: {success}/{len(results)} successful in {total_time:.1f}s")
    print(f"Rate: {len(results)/total_time:.1f} req/sec")
