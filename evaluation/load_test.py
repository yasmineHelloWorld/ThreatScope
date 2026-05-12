from locust import HttpUser, between, task


class HoneypotUser(HttpUser):
    """Run with: locust -f evaluation/load_test.py --host http://localhost:8000"""

    wait_time = between(0.1, 1.0)

    @task(6)
    def normal_browsing(self):
        self.client.get("/")
        self.client.get("/login")

    @task(2)
    def brute_force_attempt(self):
        self.client.post(
            "/login",
            data={"username": "admin", "password": "guess"},
            headers={"User-Agent": "Mozilla/5.0"},
        )

    @task(1)
    def scanner(self):
        for endpoint in ["/admin", "/debug", "/api/v1/users", "/.env"]:
            self.client.get(endpoint, name="/scan-target")

    @task(1)
    def injection_attempt(self):
        self.client.post(
            "/api/v1/login",
            json={"username": "admin", "password": "' OR 1=1--"},
        )
