import ast
import hashlib
import math
import re

import yaml

from .autopsy_domain import text_value
from .detection import FIELDS, _condition_matches, validate_dsl

CAPABILITIES = {
    "version": "socify-sigma/1",
    "logsources": [{"product": "windows", "service": "sysmon"}, {"product": "linux", "service": "auth"}, {"category": "socify_normalized"}],
    "modifiers": ["contains", "startswith", "endswith", "cidr", "exists", "all"],
    "conditions": "named selectors with and/or/not and parentheses",
    "unsupported": ["regex", "aggregations", "correlation", "base64 transforms", "of selectors", "YAML anchors/aliases/tags", "internal wildcard patterns"],
}
ALIASES = {
    "Image": "process_name",
    "ParentImage": "parent_process",
    "User": "username",
    "Computer": "hostname",
    "SourceIp": "source_ip",
    "DestinationIp": "destination_ip",
    "Hashes": "file_hash",
}


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    output = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in output:
            raise ValueError("مفتاح YAML مكرر أو غير نصي")
        output[key] = loader.construct_object(value_node, deep=deep)
    return output


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def combination(logic, conditions):
    if len(conditions) == 1:
        return conditions[0]
    return {"logic": logic, "conditions": conditions}


def leaf(field, modifier, value, sysmon):
    if field == "EventID":
        if not sysmon or modifier or type(value) not in {int, str} or not re.fullmatch(r"[0-9]{1,5}", str(value)):
            raise ValueError("EventID مدعوم فقط كرقم Sysmon دون modifier")
        return {"field": "event_type", "operator": "equals", "value": f"sysmon_{int(value)}"}
    field = ALIASES.get(field, field)
    if field not in FIELDS - {"training_run_id", "anomaly_score"}:
        raise ValueError("حقل Sigma لا يملك mapping معلنًا")
    if value is None and not modifier:
        return {"field": field, "operator": "exists", "value": False}
    if type(value) not in {str, int, float, bool} or isinstance(value, float) and not math.isfinite(value):
        raise ValueError("قيمة Sigma يجب أن تكون scalar محدودة")
    operator = {"": "equals", "contains": "contains", "startswith": "starts_with", "endswith": "ends_with", "cidr": "cidr", "exists": "exists"}.get(modifier)
    if not operator:
        raise ValueError("modifier غير مدعوم")
    if modifier == "exists" and type(value) is not bool:
        raise ValueError("exists يتطلب قيمة منطقية")
    if isinstance(value, str):
        value = text_value(value, 2048)
        if "?" in value or "*" in value.strip("*"):
            raise ValueError("wildcard داخلي غير مدعوم")
        if "*" in value:
            if modifier:
                raise ValueError("لا تجمع wildcard مع modifier في هذا الإصدار")
            if value == "*":
                return {"field": field, "operator": "exists", "value": True}
            operator = "contains" if value.startswith("*") and value.endswith("*") else "ends_with" if value.startswith("*") else "starts_with"
            value = value.strip("*")
    elif modifier in {"contains", "startswith", "endswith", "cidr"}:
        raise ValueError("هذا modifier يتطلب نصًا")
    return {"field": field, "operator": operator, "value": value}


def selector(value, sysmon):
    if not isinstance(value, dict) or not 1 <= len(value) <= 20:
        raise ValueError("selection يتطلب من 1 إلى 20 حقلًا mapped")
    fields = []
    for key, item in value.items():
        parts = key.split("|")
        field, modifiers = parts[0], parts[1:]
        if len(modifiers) != len(set(modifiers)) or set(modifiers) - set(CAPABILITIES["modifiers"]):
            raise ValueError("modifier مكرر أو غير مدعوم")
        operations = [part for part in modifiers if part != "all"]
        if len(operations) > 1:
            raise ValueError("لا يدعم الإصدار تركيب modifiers")
        values = item if isinstance(item, list) else [item]
        if not 1 <= len(values) <= 20:
            raise ValueError("قائمة Sigma خارج الحدود")
        fields.append(combination("and" if "all" in modifiers else "or", [leaf(field, operations[0] if operations else "", entry, sysmon) for entry in values]))
    return combination("and", fields)


def condition(expression, selectors):
    if not isinstance(expression, str) or len(expression) > 500 or not re.fullmatch(r"[A-Za-z0-9_ ()]+", expression):
        raise ValueError("شرط Sigma خارج لغة الشروط المدعومة")

    def visit(node, depth=0):
        if depth > 5:
            raise ValueError("تداخل شرط Sigma تجاوز الحد")
        if isinstance(node, ast.Name) and node.id in selectors:
            return selectors[node.id]
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            return combination("and" if isinstance(node.op, ast.And) else "or", [visit(child, depth + 1) for child in node.values])
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return {"logic": "not", "conditions": [visit(node.operand, depth + 1)]}
        raise ValueError("شرط Sigma يحتوي selector مجهولًا أو construct غير مدعوم")

    try:
        return visit(ast.parse(expression, mode="eval").body)
    except (SyntaxError, RecursionError) as exc:
        raise ValueError("شرط Sigma غير صالح؛ لا ينفذ أي تعبير برمجي") from exc


def compile_sigma(source):
    source = text_value(source, 65536, True)
    try:
        for index, token in enumerate(yaml.scan(source)):
            if index > 6000 or isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken)):
                raise ValueError("YAML anchors/aliases/tags أو حجم البناء غير مسموح")
        loader = UniqueLoader(source)
        try:
            document = loader.get_single_data()
        finally:
            loader.dispose()
    except (yaml.YAMLError, RecursionError, TypeError) as exc:
        raise ValueError("YAML غير صالح أو غير آمن") from exc
    if not isinstance(document, dict) or set(document) - {
        "title",
        "id",
        "status",
        "description",
        "author",
        "date",
        "modified",
        "references",
        "tags",
        "logsource",
        "detection",
        "level",
        "falsepositives",
        "license",
        "related",
    }:
        raise ValueError("حقول Sigma غير معروفة")
    logsource = document.get("logsource")
    if not isinstance(logsource, dict) or logsource not in CAPABILITIES["logsources"]:
        raise ValueError("logsource غير مدعوم؛ استخدم mapping معلنًا دون إسقاط الشروط")
    detection = document.get("detection")
    if not isinstance(detection, dict) or not 2 <= len(detection) <= 10 or "condition" not in detection:
        raise ValueError("بنية detection غير صالحة")
    selections = {
        key: selector(value, logsource.get("service") == "sysmon")
        for key, value in detection.items()
        if key != "condition" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
    }
    if len(selections) != len(detection) - 1:
        raise ValueError("اسم selection غير صالح")
    root = condition(detection["condition"], selections)
    if logsource.get("service"):
        root = combination(
            "and", [{"field": "source_type", "operator": "equals", "value": "sysmon" if logsource["service"] == "sysmon" else "linux_auth"}, root]
        )
    tags = document.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 30 or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("وسوم Sigma غير صالحة")
    mitre = [tag.removeprefix("attack.").upper() for tag in tags if re.fullmatch(r"attack\.t[0-9]{4}(?:\.[0-9]{3})?", tag.lower())]
    level = text_value(document.get("level", "medium"), 20, True)
    if level not in {"critical", "high", "medium", "low", "informational"}:
        raise ValueError("درجة Sigma غير صالحة")
    return {
        "title": text_value(document.get("title"), 150, True),
        "description": text_value(document.get("description", ""), 2000),
        "level": "low" if level == "informational" else level,
        "dsl": validate_dsl({"condition": root, "mitre_ids": mitre}),
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "compiler": CAPABILITIES["version"],
        "logsource": logsource,
    }


def validate_fixtures(compiled, fixtures):
    if not isinstance(fixtures, dict) or set(fixtures) != {"positive", "negative"}:
        raise ValueError("يلزم fixtures إيجابية وسلبية قبل النشر")
    for key in ("positive", "negative"):
        if not isinstance(fixtures[key], list) or not 1 <= len(fixtures[key]) <= 50:
            raise ValueError("يلزم من 1 إلى 50 fixture لكل فئة")
        for event in fixtures[key]:
            if not isinstance(event, dict) or set(event) - FIELDS or len(str(event)) > 10000:
                raise ValueError("fixture يتطلب حقولًا مطبعة معروفة")
            matched, _ = _condition_matches(compiled["dsl"]["condition"], event)
            if matched != (key == "positive"):
                raise ValueError("نتيجة fixture لا تطابق توقعها؛ لم تُنشر القاعدة")
