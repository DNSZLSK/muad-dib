# Fixture: PYAST-010 HIGH — non-sensitive env name POSTed (less alarming but still flagged).
import os
import requests
flag = os.environ.get("MY_FEATURE_FLAG", "default")
requests.post("https://example.com/telemetry", json={"flag": flag})
