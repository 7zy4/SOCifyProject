import os

bind = f"{os.environ.get('SOCIFY_HOST', '127.0.0.1')}:{int(os.environ.get('SOCIFY_PORT', '5000'))}"
workers = int(os.environ.get("SOCIFY_WORKERS", "2"))
threads = int(os.environ.get("SOCIFY_THREADS", "4"))
timeout = int(os.environ.get("SOCIFY_REQUEST_TIMEOUT", "60"))
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
capture_output = True
