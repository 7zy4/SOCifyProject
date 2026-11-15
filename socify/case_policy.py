"""Case access policy declared on the views that are exempt from part of the case guards.

A view that acts on a case and declares nothing gets the strict default: the case must be approved, selected and
fully accessible to the caller. A view relaxes one of those rules with ``@case_policy(...)`` placed directly under
its route decorators, so the request guards read the matched view's declaration instead of comparing endpoint or
blueprint names, and a new view is strict until someone decides otherwise.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from flask import current_app, request

ANY_METHOD = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
CaseSource = Literal["url", "body", "assignment"]


@dataclass(frozen=True)
class CasePolicy:
    # Methods usable before the case is approved and selected: pages show that state, and the approval API creates it.
    before_approval: frozenset[str] = frozenset()
    # Methods a member who may see only some of the case's import batches can still use.
    batch_member: frozenset[str] = frozenset()
    # Where the case comes from: the URL, the JSON body's case_id, or the team assignment named in the URL.
    case_from: CaseSource = "url"


STRICT = CasePolicy()


def case_policy[F: Callable[..., Any]](
    *, before_approval: Iterable[str] = (), batch_member: Iterable[str] = (), case_from: CaseSource = "url"
) -> Callable[[F], F]:
    """Declare how the case guards treat this view; anything not named keeps the strict default."""
    policy = CasePolicy(frozenset(before_approval), frozenset(batch_member), case_from)
    if not policy.before_approval | policy.batch_member <= ANY_METHOD or case_from not in ("url", "body", "assignment"):
        raise ValueError(f"invalid case policy {policy}")

    def declare(view: F) -> F:
        view.case_policy = policy  # type: ignore[attr-defined]
        return view

    return declare


def declared_policy() -> CasePolicy:
    """Policy of the view matched by the current request."""
    policy = getattr(current_app.view_functions.get(request.endpoint or ""), "case_policy", STRICT)
    return policy if isinstance(policy, CasePolicy) else STRICT
