import threading
import requests

def send_request(visitor_id):
    try:
        response = requests.get("https://www.munowatch.com/")
        print(f"Visitor {visitor_id}: Status Code: {response.status_code}")
    except Exception as e:
        print(f"Visitor {visitor_id}: Request failed with error: {e}")

# Create two threads, simulating 2 visitors
threads = []
for i in range(200000000000000000000000):
    thread = threading.Thread(target=send_request, args=(i + 1000000000000000000000000000000000000000,))
    threads.append(thread)
    thread.start()

# Wait for both threads to complete
for thread in threads:
    thread.join()
