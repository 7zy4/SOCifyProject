"""Protocol-boundary checks, excluded from simulated-user counts."""

from tests.e2e.document_requests import DocumentRequests


class Session:
    def on(self, _name, _callback):
        pass

    def send(self, name):
        return {"frameTree": {"frame": {"id": "main", "loaderId": "old"}}} if name == "Page.getFrameTree" else {}


def request(identifier, loader, frame="main", url="https://observer.invalid/same"):
    return {"requestId": identifier, "loaderId": loader, "frameId": frame, "request": {"url": url, "method": "GET"}, "type": "Fetch"}


def test_document_identity_separates_identical_urls_and_late_events():
    observer = DocumentRequests(None, Session())
    observer.started(request("navigation", "new"))
    observer.started(request("late-old", "old"))
    observer.started(request("early-new", "new"))
    assert set(observer.pending) == {"navigation", "late-old", "early-new"}
    observer.committed({"frame": {"id": "main", "loaderId": "new"}})
    assert set(observer.pending) == {"navigation", "early-new"}
    observer.started(request("delivered-after-commit", "old"))
    observer.finished({"requestId": "late-old", "errorText": "net::ERR_ABORTED"})
    assert set(observer.pending) == {"navigation", "early-new"}
    observer.finished({"requestId": "navigation"})
    observer.finished({"requestId": "early-new"})
    assert not observer.pending


def test_failed_navigation_does_not_retire_current_document():
    observer = DocumentRequests(None, Session())
    observer.started(request("active", "old"))
    observer.started(request("navigation", "uncommitted"))
    observer.finished({"requestId": "navigation", "errorText": "net::ERR_ABORTED"})
    assert set(observer.pending) == {"active"}
    assert not observer.retirements


def test_frame_removal_retires_only_that_frame_and_never_unknown_workers():
    observer = DocumentRequests(None, Session())
    observer.committed({"frame": {"id": "child", "loaderId": "child-document"}})
    observer.started(request("main", "old"))
    observer.started(request("child", "child-document", "child"))
    observer.started(request("worker", "", ""))
    observer.detached({"frameId": "child", "reason": "swap"})
    assert set(observer.pending) == {"main", "child", "worker"}
    observer.detached({"frameId": "child", "reason": "remove"})
    assert set(observer.pending) == {"main", "worker"}


def test_redirect_remains_pending_until_its_final_response_finishes():
    observer = DocumentRequests(None, Session())
    observer.started(request("redirect", "old", url="https://observer.invalid/start"))
    observer.started(request("redirect", "old", url="https://observer.invalid/end"))
    assert len(observer.pending) == 1
    assert observer.pending["redirect"].url.endswith("/end")
    observer.finished({"requestId": "redirect"})
    assert not observer.pending
