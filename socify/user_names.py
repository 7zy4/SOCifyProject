"""User-authored display names, selected by interface language."""

from flask import has_request_context, request


def localized_name(name, name_ar, name_en):
    language = "ar"
    if has_request_context():
        language = request.headers.get("X-SOCify-Language", request.cookies.get("socify-language", "ar"))
    return (name_en if language == "en" else name_ar) or name
