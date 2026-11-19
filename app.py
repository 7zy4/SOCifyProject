"""The WSGI entry point: Gunicorn serves app:app (see Dockerfile and gunicorn.conf.py)."""

from socify import create_app

app = create_app()
