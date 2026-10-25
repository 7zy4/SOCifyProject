from flask import Request


class StructureLimitError(RuntimeError):
    pass


def validate_json_structure(value, max_nodes=200000):
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if depth > 32 or visited > max_nodes:
            raise StructureLimitError("JSON structure exceeds configured depth or item budget")
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        if visited + len(pending) + len(children) > max_nodes:
            raise StructureLimitError("JSON structure exceeds configured item budget")
        pending.extend((child, depth + 1) for child in children)


class BoundedRequest(Request):
    def get_json(self, force=False, silent=False, cache=True):
        result = super().get_json(force=force, silent=silent, cache=cache)
        validate_json_structure(result)
        return result
