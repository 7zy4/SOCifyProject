"""Translate recognized system task templates without rewriting authored content."""

from flask import has_request_context, request

TITLES = {
    "validate_evidence": ("Validate primary evidence", "التحقق من الدليل الأساسي"),
    "document_response": ("Document response decision", "توثيق قرار الاستجابة"),
}


def task_title(title, system_key, language=None):
    template = TITLES.get(system_key)
    if not template or title != template[0]:
        return title
    if language is None:
        language = request.headers.get("X-SOCify-Language", request.cookies.get("socify-language", "ar")) if has_request_context() else "ar"
    return template[0] if language == "en" else template[1]


def task_view(row):
    item = dict(row)
    return {**item, "display_title": task_title(item["title"], item.get("system_key"))}
