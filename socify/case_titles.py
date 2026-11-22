"""Case names given in Arabic and English, shown in the interface language.

The creator writes both names, so codes and abbreviations in the name are never machine translated.
A case without an English name keeps its original name in both languages.
"""

from flask import has_request_context, request


def localized_case_title(title, title_en):
    language = "ar"
    if has_request_context():
        language = request.headers.get("X-SOCify-Language", request.cookies.get("socify-language", "ar"))
    return (title_en if language == "en" else None) or title
