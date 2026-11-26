"""Flask extensions shared by the application factory and the modules that need them."""

from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
