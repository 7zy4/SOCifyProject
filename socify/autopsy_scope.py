from .timeutils import parse_timestamp, utc_now


def investigation_scope(records, now=None):
    current = now or utc_now()
    counts = dict.fromkeys(("confirmed", "suspected", "checked_clear", "unexamined", "undetermined"), 0)
    for asset in records.get("asset", []):
        assessment = asset.get("assessment")
        counts[assessment if isinstance(assessment, str) and assessment in counts else "undetermined"] += 1
    candidates = []
    excluded = 0
    for foothold in records.get("foothold", []):
        try:
            moment = parse_timestamp(foothold.get("first_observed_at"))
            if not foothold.get("evidence_id") or not foothold.get("asset_id") or moment > current:
                raise ValueError("Unverified or future observation")
        except (ValueError, TypeError, OverflowError):
            excluded += 1
            continue
        candidates.append((moment, foothold))
    earliest = min(candidates, key=lambda item: item[0])[1] if candidates else None
    return {
        "asset_records": sum(counts.values()),
        "counts_by_assessment": counts,
        "earliest_retained_observation": {key: earliest.get(key) for key in ("asset_id", "evidence_id", "first_observed_at", "confidence", "limitations")}
        if earliest
        else None,
        "excluded_observations": excluded,
        "limitations": "التصنيف تقييم المحقق لأصول موثقة وليس حصرًا آليًا لجميع أجهزة الشركة. أقدم ملاحظة محفوظة مدعومة بدليل لا تثبت Patient Zero أو بداية الهجوم. غياب أصل أو فحص لا يثبت سلامته؛ لا تُدمج سجلات أصول مختلفة اعتمادًا على الاسم وحده.",
    }
